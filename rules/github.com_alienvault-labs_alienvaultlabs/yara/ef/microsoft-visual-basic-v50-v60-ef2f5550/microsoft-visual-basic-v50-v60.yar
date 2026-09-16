rule _Microsoft_Visual_Basic_v50__v60_
{
	meta:
		description = "Microsoft Visual Basic v5.0 / v6.0"
	strings:
		$0 = {5A 68 68 52 E9}
	condition:
		$0 at entrypoint
}