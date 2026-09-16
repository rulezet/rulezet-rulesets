import "pe"
rule _FSG_110_Eng__dulekxt__MASM32__TASM32_
{
	meta:
		description = "FSG 1.10 (Eng) -> dulek/xt -> (MASM32 / TASM32)"
	strings:
		$0 = {1B DB E8 02 00 00 00 1A 0D 5B 68 80 ?? ?? 00 E8 01 00 00 00 EA 5A 58 EB 02 CD 20 68 F4 00 00 00 EB 02 CD 20 5E 0F B6 D0 80 CA 5C 8B 38 EB 01 35 EB 02 DC 97 81 EF F7 65 17 43 E8 02 00 00 00 97 CB 5B 81 C7 B2 8B A1 0C 8B D1 83 EF 17 EB 02 0C 65 83 EF 43 13}
	condition:
		$0 at pe.entry_point
}