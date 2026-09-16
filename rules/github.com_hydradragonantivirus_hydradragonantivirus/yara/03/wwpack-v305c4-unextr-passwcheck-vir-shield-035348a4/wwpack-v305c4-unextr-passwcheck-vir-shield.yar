import "pe"
rule _WWPACK_v305c4_Unextr_Passwcheck_Vir_shield_
{
	meta:
		description = "WWPACK v3.05c4 (Unextr. Passw.check. Vir. shield)"
	strings:
		$0 = {03 05 C0 1B B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 B1 ?? 51 8C D3}
	condition:
		$0 at pe.entry_point
}