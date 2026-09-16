import "pe"
rule UpxLock1012CyberDoomTeamXBoBBobSoft_oldsig
{
	meta:
		author="malware-lu"
strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 48 12 40 00 60 E8 2B 03 00 00 61 }

condition:
		$a0 at pe.entry_point
}