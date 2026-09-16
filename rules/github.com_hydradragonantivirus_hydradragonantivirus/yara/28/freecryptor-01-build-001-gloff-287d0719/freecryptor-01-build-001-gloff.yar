import "pe"
rule _FreeCryptor_01_build_001__GlOFF_
{
	meta:
		description = "FreeCryptor 0.1 (build 001) -> GlOFF"
	strings:
		$0 = {8B 04 24 40 90 83 C0 07 80 38 90 90 74 02 EB FF 68 26 ?? ?? 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 FF E4 90 8B 04 24 64 A3 00 00 00 00 8B 64 24 08 90 83 C4 08}
	condition:
		$0 at pe.entry_point
}