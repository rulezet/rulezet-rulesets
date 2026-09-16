import "pe"
rule __Protector_v1111_DDeMPE_Engine_v09_DDeMCI_v092_
{
	meta:
		description = "*** Protector v1.1.11 (DDeM->PE Engine v0.9, DDeM->CI v0.9.2)"
	strings:
		$0 = {E9 ?? ?? E9 ?? ?? E9 ?? ??}
	condition:
		$0 at pe.entry_point
}