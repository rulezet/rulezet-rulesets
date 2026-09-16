rule _PESHiELD_v025_
{
	meta:
		description = "PESHiELD v0.25"
	strings:
		$0 = {5D 83 ED 06 EB 02 EA 04}
	condition:
		$0 at entrypoint
}