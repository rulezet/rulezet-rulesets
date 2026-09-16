rule _tElock_v071_
{
	meta:
		description = "tElock v0.71"
	strings:
		$0 = {60 E8 44 11 ?? ?? C3}
	condition:
		$0 at entrypoint
}