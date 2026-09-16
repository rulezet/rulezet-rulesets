rule RansomSampleLockyCrypt
{
	meta:
		Description  = "Ransom.Win32.Locky.sm"
		ThreatLevel  = "5"

	strings:
		$s1 = ".locky" ascii wide nocase
		$ = "&encrypted=" ascii wide nocase
		$s2 = "_Locky_recover_instructions.txt" ascii wide nocase
		$s3 = "_Locky_recover_instructions.bmp" ascii wide nocase
		$ = "94.242.57.45" ascii wide nocase
		$ = "46.4.239.76" ascii wide nocase
		$s6 = "Software\\Locky" ascii wide nocase
		$ = "vssadmin.exe Delete Shadows" ascii wide nocase
		$ = "Locky" ascii wide nocase

		$o1 = { 45 b8 99 f7 f9 0f af 45 b8 89 45 b8 } 		$o2 = { 2b 0a 0f af 4d f8 89 4d f8 c7 45 } 
	condition:
		(3 of them) or (any of ($s*)) or (all of ($o*))
}