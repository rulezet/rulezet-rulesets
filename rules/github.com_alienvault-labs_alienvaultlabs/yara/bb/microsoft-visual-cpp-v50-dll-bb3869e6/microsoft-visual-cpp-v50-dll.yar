rule _Microsoft_Visual_Cpp_v50_DLL_
{
	meta:
		description = "Microsoft Visual C++ v5.0 DLL"
	strings:
		$0 = {55 8B EC 6A FF 68 68 64 A1 ?? ?? ?? ??}
	condition:
		$0 at entrypoint
}