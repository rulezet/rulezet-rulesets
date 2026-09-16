rule _Microsoft_Visual_Cpp_vxx_
{
	meta:
		description = "Microsoft Visual C++ vx.x"
	strings:
		$0 = {53 55 56 8B 85 F6 57 B8 75 8B 85 C9 75 33 C0 5F 5E 5D 5B}
		$1 = {64 A1 ?? ?? ?? ?? 55 8B EC 6A FF 68 68 50 64 89 25 ?? ?? ?? ?? 83 EC 53 56}
		$2 = {55 8B EC 83 EC 44 56 FF 15 8B F0 8A 3C}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint
}