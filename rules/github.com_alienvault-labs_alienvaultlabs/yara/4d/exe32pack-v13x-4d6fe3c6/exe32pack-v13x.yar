rule _EXE32Pack_v13x_
{
	meta:
		description = "EXE32Pack v1.3x"
	strings:
		$0 = {E8 24 8B 4C 24 0C C7 01 17 01 C7 81 31 C0 89 41 14 89 41 18 80}
	condition:
		$0 at entrypoint
}