rule _PESHiELD_v02__v02b__v02b2_
{
	meta:
		description = "PESHiELD v0.2 / v0.2b / v0.2b2"
	strings:
		$0 = {60 E8}
	condition:
		$0 at entrypoint
}