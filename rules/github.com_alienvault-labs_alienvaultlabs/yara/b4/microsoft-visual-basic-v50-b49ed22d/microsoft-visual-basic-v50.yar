rule _Microsoft_Visual_Basic_v50_
{
	meta:
		description = "Microsoft Visual Basic v5.0"
	strings:
		$0 = {68}
	condition:
		$0 at entrypoint
}