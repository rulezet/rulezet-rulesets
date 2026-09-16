rule RCryptor1_6b_1_6c__Vaska
{
	meta:
		author = "PEiD"
		description = "RCryptor 1.6b / 1.6c -> Vaska"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 8B C7 03 04 24 2B C7 80 38 50 0F 85 1B 8B 1F FF 68 }
	condition:
		$a0
}