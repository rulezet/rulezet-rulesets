import "pe"
rule _Go32Stub_v200_DOSExtender_
{
	meta:
		description = "Go32Stub v.2.00 DOS-Extender"
	strings:
		$0 = {0E 1F 8C 1E ?? ?? 8C 06 ?? ?? FC B4 30 CD 21 80}
	condition:
		$0 at pe.entry_point
}