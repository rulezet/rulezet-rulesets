rule _Microsoft_Visual_Cpp_v42_
{
	meta:
		description = "Microsoft Visual C++ v4.2"
	strings:
		$0 = {64 A1 ?? ?? ?? ?? 55 8B EC 6A FF 68 68 50 64 83 53 56 57 89}
		$1 = {53 B8 8B 56 57 85 DB 55}
	condition:
		$0 at entrypoint or $1 at entrypoint
}