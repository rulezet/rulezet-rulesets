rule _Microsoft_Visual_Cpp_v70_
{
	meta:
		description = "Microsoft Visual C++ v7.0"
	strings:
		$0 = {6A 68}
		$1 = {55 8D 6C 81 EC 8B 45 83 F8 01 56 0F 84 85 C0 0F}
	condition:
		$0 at entrypoint or $1 at entrypoint
}