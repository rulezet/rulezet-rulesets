import "pe"
rule _WWPACK_v302_v302a_v304_Relocations_pack_
{
	meta:
		description = "WWPACK v3.02, v3.02a, v3.04 (Relocations pack)"
	strings:
		$0 = {BE ?? ?? BF ?? ?? B9 ?? ?? 8C CD 81 ED ?? ?? 8B DD 81 EB ?? ?? 8B D3 FC FA 1E 8E DB 01 15 33 C0 2E AC}
	condition:
		$0 at pe.entry_point
}