rule _SPEC_b2_
{
	meta:
		description = "SPEC b2"
	strings:
		$0 = {5B 53 50 45 43 5D E8 5D 8B C5 81 ED 41 24 40 2B 85 89 26 40 83 E8 0B 89 85 8D 26 40 0F B6 B5 91 26 40 8B}
	condition:
		$0 at entrypoint
}