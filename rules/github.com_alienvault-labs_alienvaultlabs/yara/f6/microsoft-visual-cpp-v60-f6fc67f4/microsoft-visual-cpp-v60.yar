rule _Microsoft_Visual_Cpp_v60_
{
	meta:
		description = "Microsoft Visual C++ v6.0"
	strings:
		$0 = {51}
		$1 = {55 8D 6C 81 EC 8B 45 83 F8 01 56 0F 84 85 C0 0F}
		$2 = {55 8B EC 51}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint
}