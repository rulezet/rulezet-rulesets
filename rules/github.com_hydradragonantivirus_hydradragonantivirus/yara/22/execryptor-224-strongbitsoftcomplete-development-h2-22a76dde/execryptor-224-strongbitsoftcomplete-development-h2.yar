import "pe"
rule _EXECryptor_224__StrongbitSoftComplete_Development_h2_
{
	meta:
		description = "EXECryptor 2.2.4 -> Strongbit/SoftComplete Development (h2)"
	strings:
		$0 = {E8 F7 FE FF FF 05 ?? ?? 00 00 FF E0 E8 EB FE FF FF 05 ?? ?? 00 00 FF E0 E8 ?? 00 00 00}
	condition:
		$0 at pe.entry_point
}