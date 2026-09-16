rule _Microsoft_Visual_Cpp_v60_SPx_
{
	meta:
		description = "Microsoft Visual C++ v6.0 SPx"
	strings:
		$0 = {55 8B EC 83 EC 44 56 FF 15 6A 01 8B F0 FF}
		$1 = {55 8B EC 6A FF 68 68 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 53 56}
	condition:
		$0 at entrypoint or $1 at entrypoint
}