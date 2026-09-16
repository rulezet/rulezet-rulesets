import "pe"
rule _SVKProtector_v132_
{
	meta:
		description = "SVK-Protector v1.32"
	strings:
		$0 = {64 8B 05 55 8B EC 6A FF 68 40 68 40 50 64 89 25 83 EC 08 50 53 56 57 89 65 E8 C7 45}
	condition:
		$0 at pe.entry_point
}