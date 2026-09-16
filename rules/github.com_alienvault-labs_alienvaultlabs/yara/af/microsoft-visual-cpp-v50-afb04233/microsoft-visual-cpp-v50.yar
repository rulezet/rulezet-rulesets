rule _Microsoft_Visual_Cpp_v50_
{
	meta:
		description = "Microsoft Visual C++ v5.0"
	strings:
		$0 = {24 ?? 8B 24}
	condition:
		$0 at entrypoint
}