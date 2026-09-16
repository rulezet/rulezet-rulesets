rule RogueWinwebsecSample
{
	meta:
		Description  = "Rogue.Winwebsec.sm"
		ThreatLevel  = "5"

	strings:
		$a = "%s%s\\%s.ico" ascii wide
		$b = "%s%s\\%s.exe" ascii wide
	condition:
		$a or $b
}