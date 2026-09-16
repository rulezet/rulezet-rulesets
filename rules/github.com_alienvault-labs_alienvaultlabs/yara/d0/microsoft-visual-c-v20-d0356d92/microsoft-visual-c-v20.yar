rule _Microsoft_Visual_C_v20_
{
	meta:
		description = "Microsoft Visual C v2.0"
	strings:
		$0 = {55 8B EC 56 57 BF 8B 3B F7}
	condition:
		$0 at entrypoint
}