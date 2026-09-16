rule _Microsoft_Visual_Cpp_v70_DLL_
{
	meta:
		description = "Microsoft Visual C++ v7.0 DLL"
	strings:
		$0 = {55 8B EC 53 8B 5D 08 56 8B 75 0C 57 8B 7D 10}
		$1 = {FF 25 ??}
	condition:
		$0 at entrypoint or $1 at entrypoint
}