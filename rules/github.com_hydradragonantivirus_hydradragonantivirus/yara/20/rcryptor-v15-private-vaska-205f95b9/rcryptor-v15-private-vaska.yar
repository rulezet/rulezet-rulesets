import "pe"
rule _RCryptor_v15_Private__Vaska_
{
	meta:
		description = "RCryptor v1.5 (Private) --> Vaska"
	strings:
		$0 = {83 2C 24 4F 68 ?? ?? ?? ?? FF 54 24 04 83 44 24 04 4F B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3}
	condition:
		$0 at pe.entry_point
}