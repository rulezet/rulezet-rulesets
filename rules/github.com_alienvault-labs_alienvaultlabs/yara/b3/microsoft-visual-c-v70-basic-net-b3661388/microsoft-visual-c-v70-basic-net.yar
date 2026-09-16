rule _Microsoft_Visual_C_v70__Basic_NET_
{
	meta:
		description = "Microsoft Visual C# v7.0 / Basic .NET"
	strings:
		$0 = {53 55 56 8B 74 24 14 85 F6 57 B8}
	condition:
		$0 at entrypoint
}