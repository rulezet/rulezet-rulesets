rule _Microsoft_Visual_Cpp_v4x_
{
	meta:
		description = "Microsoft Visual C++ v4.x"
	strings:
		$0 = {64 A1 ?? ?? ?? ?? 55 8B EC 6A FF 68 68 50 64 83 53 56 57 89}
	condition:
		$0 at entrypoint
}