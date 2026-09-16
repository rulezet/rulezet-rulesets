rule TrojanDownloaderWin32PerkeshDriverSamle
{
	meta:
		Description  = "Trojan.Perkesh.rc"
		ThreatLevel  = "5"
	strings:
		$a = "C:\\FOUND.001\\333888\\sys\\Driver\\i386\\feiji.pdb" ascii wide
	condition:
		$a
}