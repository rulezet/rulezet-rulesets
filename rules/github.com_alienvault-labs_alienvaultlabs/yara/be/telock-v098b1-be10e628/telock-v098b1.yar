rule _tElock_v098b1_
{
	meta:
		description = "tElock v0.98b1"
	strings:
		$0 = {E9 1B E4 FF}
	condition:
		$0 at entrypoint
}