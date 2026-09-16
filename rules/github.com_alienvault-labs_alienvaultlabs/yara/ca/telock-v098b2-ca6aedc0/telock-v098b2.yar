rule _tElock_v098b2_
{
	meta:
		description = "tElock v0.98b2"
	strings:
		$0 = {E9 FF FF ?? ?? ?? ?? ?? ?? ??}
	condition:
		$0 at entrypoint
}