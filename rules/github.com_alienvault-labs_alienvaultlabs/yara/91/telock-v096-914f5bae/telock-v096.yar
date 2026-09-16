rule _tElock_v096_
{
	meta:
		description = "tElock v0.96"
	strings:
		$0 = {E9 25 E4 FF FF ?? ?? ??}
	condition:
		$0 at entrypoint
}