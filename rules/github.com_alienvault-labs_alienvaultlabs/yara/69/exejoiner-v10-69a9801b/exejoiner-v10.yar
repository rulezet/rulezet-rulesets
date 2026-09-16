rule _EXEJoiner_v10_
{
	meta:
		description = "EXEJoiner v1.0"
	strings:
		$0 = {9C FE 03 60 BE 41 8D BE 10 FF FF 57 83 CD FF EB}
	condition:
		$0 at entrypoint
}