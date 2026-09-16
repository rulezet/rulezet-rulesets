rule _Microsoft_Visual_Cpp_v50v60_MFC_
{
	meta:
		description = "Microsoft Visual C++ v5.0/v6.0 (MFC)"
	strings:
		$0 = {55 8B EC ??}
	condition:
		$0 at entrypoint
}