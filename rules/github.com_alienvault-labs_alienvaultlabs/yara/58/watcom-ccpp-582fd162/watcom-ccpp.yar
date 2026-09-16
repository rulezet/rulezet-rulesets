rule _WATCOM_CCpp_
{
	meta:
		description = "WATCOM C/C++"
	strings:
		$0 = {53 56 57 55 8B 74 24 14 8B 7C 24 18 8B 6C 24 1C 83 FF 03 0F}
	condition:
		$0 at entrypoint
}