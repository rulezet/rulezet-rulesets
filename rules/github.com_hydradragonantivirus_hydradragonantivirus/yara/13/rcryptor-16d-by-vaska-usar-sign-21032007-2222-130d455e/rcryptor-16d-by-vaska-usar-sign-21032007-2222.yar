import "pe"
rule _RCryptor_16d_by_Vaska_UsAr_sign__21032007_2222_
{
	meta:
		description = "RCryptor 1.6d by Vaska (UsAr sign  21.03.2007 22:22)"
	strings:
		$0 = {60 90 61 61 80 7F F0 45 90 60 0F 85 1B 8B 1F FF 68 40 A1 14 13 B8 00 10 14 13 90 3D 24 C0 14 13 74 06 80 30 F6 40 EB F3 B8 8C 20 18 13 90 3D B9 27 18 13 74 06 80 30 89 40 EB F3 C3}
	condition:
		$0 at pe.entry_point
}