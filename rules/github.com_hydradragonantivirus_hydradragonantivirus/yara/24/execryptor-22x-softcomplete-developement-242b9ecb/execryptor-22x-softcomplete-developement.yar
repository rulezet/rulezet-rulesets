import "pe"
rule _EXECryptor_22x__SoftComplete_Developement_
{
	meta:
		description = "EXECryptor 2.2.x -> SoftComplete Developement"
	strings:
		$0 = {E8 F7 FE FF FF 05 ?? ?? 00 00 FF E0 E8 EB FE FF FF 05 ?? ?? 00 00 FF E0 E8 04 00 00 00 FF FF FF FF}
	condition:
		$0 at pe.entry_point
}