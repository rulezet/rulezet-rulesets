rule _Microsoft_Visual_Cpp_v60_Debug_Version_
{
	meta:
		description = "Microsoft Visual C++ v6.0 (Debug Version)"
	strings:
		$0 = {6A 68 E8 BF 8B C7 E8 89 65 8B F4 89 3E 56 FF 15 8B 4E 89 0D 8B 46}
	condition:
		$0 at entrypoint
}