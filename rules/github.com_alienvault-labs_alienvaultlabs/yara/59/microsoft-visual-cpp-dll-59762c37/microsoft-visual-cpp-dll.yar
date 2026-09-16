rule _Microsoft_Visual_Cpp_DLL_
{
	meta:
		description = "Microsoft Visual C++ DLL"
	strings:
		$0 = {53 56 57 BB 01 8B 24}
		$1 = {53 B8 01 ?? ?? ?? 8B 5C 24 0C 56 57 85 DB 55 75 12 83 3D 75 09 33}
		$2 = {55 8B EC 56 57 BF 01 ?? ?? ?? 8B 75}
		$3 = {55 8B EC 6A FF 68 68 64 A1 ?? ?? ?? ?? 50 64 89}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint or $3 at entrypoint
}