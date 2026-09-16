rule _Microsoft_Visual_Cpp_v60_DLL_
{
	meta:
		description = "Microsoft Visual C++ v6.0 DLL"
	strings:
		$0 = {83 7C 24 08 01 75 09 8B 44 24 04 A3 ?? 10 E8 8B FF FF}
		$1 = {55 8B EC 83 EC 50 53 56 57 BE 8D 7D F4 A5 A5 66 A5}
		$2 = {55 8B EC 53 8B 5D 08 56 8B 75}
		$3 = {0D ??}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint or $3 at entrypoint
}