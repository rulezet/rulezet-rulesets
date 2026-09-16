import "pe"
rule _RCryptor_v15__Vaska_
{
	meta:
		description = "RCryptor v1.5 --> Vaska"
	strings:
		$0 = {83 2C 24 4F 68 ?? ?? ?? ?? FF 54 24 04 83 44 24 04 4F}
	condition:
		$0 at pe.entry_point
}