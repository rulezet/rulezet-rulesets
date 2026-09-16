rule _Nullsoft_Install_System_v198_
{
	meta:
		description = "Nullsoft Install System v1.98"
	strings:
		$0 = {83 EC 0C 53 55 56 57 FF 15 70 40 ?? 8B 35 92 40 ?? 05 E8 03 ?? ?? 89 44 24 14 B3 20 FF 15 2C 70 40 ?? BF ?? 04 ?? ?? 68 ?? 57 FF 15 40 ?? 57 FF}
	condition:
		$0 at entrypoint
}