import "pe"
rule RansomLocky
{
	meta:
		Description  = "Ransom.Locky.ab"
		ThreatLevel  = "5"
	strings:
		$mz = { 4d 5a }

		$inst1 = "_HELP_instructions.bmp" ascii wide
		$inst2 = "_HELP_instructions.html" ascii wide
		$inst3 = "_HELP_instructions.txt" ascii wide
		$inst4 = "_Locky_recover_instructions.bmp" ascii wide
		$inst5 = "_Locky_recover_instructions.txt" ascii wide
		$deleteShadows = "vssadmin.exe" ascii wide 
		$cyrptEP1 = {e8 95 23 ff ff 86 c8 86 ea e9 8d 23 ff ff 86 f4 e9 84 23 ff ff 86 c5} 		$cyrptEP2 = {55 8b ec eb 68 eb 66 eb 64 6a 00 6a 00 6a 00 6a 00 6a 00} 	
	condition:
		( $mz at 0 ) and 
		(
			$cyrptEP1 at pe.entry_point or
			$cyrptEP2 at pe.entry_point or 
			(any of ($inst*)) or 
			$deleteShadows
		)
}