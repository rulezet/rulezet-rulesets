rule _Free_Pascal_v09910_
{
	meta:
		description = "Free Pascal v0.99.10"
	strings:
		$0 = {64 A1 55 89 E5 6A FF 68 68 9A 10 40}
	condition:
		$0 at entrypoint
}