import "pe"
rule _EXECryptor_V2X__SoftComplete_Developement_
{
	meta:
		description = "EXECryptor V2.X -> SoftComplete Developement"
	strings:
		$0 = {A4 ?? ?? 00 00 00 00 00 FF FF FF FF 3C ?? ?? 00 94 ?? ?? 00 D8 ?? ?? 00 00 00 00 00 FF FF FF FF}
	condition:
		$0 at pe.entry_point
}