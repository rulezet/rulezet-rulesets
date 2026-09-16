import "pe"
rule _RCryptor_v13__v14__Vaska_
{
	meta:
		description = "RCryptor v1.3 / v1.4 --> Vaska"
	strings:
		$0 = {55 8B EC 8B 44 24 04 83 E8 4F 68 ?? ?? ?? ?? FF D0 58 59 50}
		$1 = {55 8B EC 8B 44 24 04 83 E8 4F 68 ?? ?? ?? ?? FF D0 58 59 50 B8 ?? ?? ?? ?? 3D ?? ?? ?? ?? 74 06 80 30 ?? 40 EB F3}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}