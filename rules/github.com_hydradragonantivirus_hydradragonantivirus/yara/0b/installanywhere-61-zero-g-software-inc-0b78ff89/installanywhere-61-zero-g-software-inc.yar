import "pe"
rule _InstallAnywhere_61_Zero_G_Software_Inc_
{
	meta:
		description = "InstallAnywhere 6.1 ->Zero G Software Inc"
	strings:
		$0 = {60 BE 00 A0 42 00 8D BE 00 70 FD FF 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07}
	condition:
		$0 at pe.entry_point
}