rule RCryptor1_3_1_4__Vaska
{
	meta:
		author = "PEiD"
		description = "RCryptor 1.3 / 1.4 -> Vaska"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 55 8B EC 8B 44 24 04 83 E8 4F 68 ?? ?? ?? ?? FF D0 58 59 50 }
	condition:
		$a0
}