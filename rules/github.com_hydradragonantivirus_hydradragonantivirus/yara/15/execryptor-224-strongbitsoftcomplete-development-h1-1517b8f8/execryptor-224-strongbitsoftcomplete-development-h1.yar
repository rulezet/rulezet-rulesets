import "pe"
rule _EXECryptor_224__StrongbitSoftComplete_Development_h1_
{
	meta:
		description = "EXECryptor 2.2.4 -> Strongbit/SoftComplete Development (h1)"
	strings:
		$0 = {E8 F7 FE FF FF 05 ?? ?? 00 00 FF E0 E8 EB FE FF FF 05 ?? ?? 00 00 FF E0 E8 04 00 00 00 FF FF FF FF 5E C3}
	condition:
		$0 at pe.entry_point
}