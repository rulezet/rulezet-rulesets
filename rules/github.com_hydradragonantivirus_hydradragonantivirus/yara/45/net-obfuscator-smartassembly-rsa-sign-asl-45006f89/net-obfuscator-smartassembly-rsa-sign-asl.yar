import "pe"
rule _NET_Obfuscator_Smartassembly__RSA_sign_ASL_
{
	meta:
		description = ".NET Obfuscator Smartassembly - RSA sign ASL"
	strings:
		$0 = {52 53 41 31 00 04 00 00 01 00 01 00 8F C1 0F 45 44 06 BF 85 56 8F 95 86 75 56 73 83 EB 34 4E F5 16 BE C3 93 7A AD 92 39 B1 5E DF 1E B6 63 E2 50 1C E2}
	condition:
		$0 at pe.entry_point
}