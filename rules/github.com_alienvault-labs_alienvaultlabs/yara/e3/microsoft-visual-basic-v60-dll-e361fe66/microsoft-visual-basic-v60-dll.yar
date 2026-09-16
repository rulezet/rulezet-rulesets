rule _Microsoft_Visual_Basic_v60_DLL_
{
	meta:
		description = "Microsoft Visual Basic v6.0 DLL"
	strings:
		$0 = {55 89 E5 E8 C9 C3 45 58}
	condition:
		$0 at entrypoint
}