rule RCryptor1_6__Vaska
{
	meta:
		author = "PEiD"
		description = "RCryptor 1.6 -> Vaska"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 33 D0 68 ?? ?? ?? ?? FF D2 }
	condition:
		$a0
}