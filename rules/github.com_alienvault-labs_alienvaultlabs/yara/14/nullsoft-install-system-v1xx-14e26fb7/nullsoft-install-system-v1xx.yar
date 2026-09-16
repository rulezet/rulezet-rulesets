rule _Nullsoft_Install_System_v1xx_
{
	meta:
		description = "Nullsoft Install System v1.xx"
	strings:
		$0 = {83 EC 0C 53 56 57 FF 15 20 71 40 ?? 05 E8 03 ?? ?? BE 60 FD 41 ?? 89 44 24 10 B3 20 FF 15 28 70 40 ?? 68 ?? 04 ?? ?? FF 15 28 71 40 ?? 50 56 FF 15 08 71 40 ?? 80 3D 60 FD 41 ?? 22 75 08 80}
		$1 = {83 EC 0C 53 56 57 FF 15 2C 81}
	condition:
		$0 at entrypoint or $1 at entrypoint
}