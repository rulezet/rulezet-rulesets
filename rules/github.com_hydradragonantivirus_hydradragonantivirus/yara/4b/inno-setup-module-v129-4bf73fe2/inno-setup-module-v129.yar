import "pe"
rule _Inno_Setup_Module_v129_
{
	meta:
		description = "Inno Setup Module v1.2.9"
	strings:
		$0 = {55 8B EC 81 EC 14 ?? ?? 53 56 57 6A ?? FF 15 68 FF 15 85 C0 74}
	condition:
		$0 at pe.entry_point
}