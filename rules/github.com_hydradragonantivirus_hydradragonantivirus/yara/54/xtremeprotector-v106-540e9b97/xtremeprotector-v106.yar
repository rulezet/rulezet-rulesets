import "pe"
rule _XtremeProtector_v106_
{
	meta:
		description = "Xtreme-Protector v1.06"
	strings:
		$0 = {60 8B F0 33 DB 83 C3 01 83 C0}
	condition:
		$0 at pe.entry_point
}