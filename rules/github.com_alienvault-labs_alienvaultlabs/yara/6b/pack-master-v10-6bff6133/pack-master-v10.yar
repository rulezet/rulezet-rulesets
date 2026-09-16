rule _Pack_Master_v10_
{
	meta:
		description = "Pack Master v1.0"
	strings:
		$0 = {53 51 52 56 57 55 E8 ?? ?? ?? ?? 5D 8B CD 81 ED 33 30 40 2B 8D EE 32 40 ?? 83 E9 0B 89 8D F2 32 40 80 BD D1 32 40 01 0F}
		$1 = {9C 60 E8 02 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 40 87 DD 6A 04 68 10 68 02 6A FF}
	condition:
		$0 at entrypoint or $1 at entrypoint
}