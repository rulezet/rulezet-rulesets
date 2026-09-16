rule _Microsoft_Visual_Cpp_v42_DLL_
{
	meta:
		description = "Microsoft Visual C++ v4.2 DLL"
	strings:
		$0 = {55 8B EC 6A FF 68 68 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 53 56}
	condition:
		$0 at entrypoint
}