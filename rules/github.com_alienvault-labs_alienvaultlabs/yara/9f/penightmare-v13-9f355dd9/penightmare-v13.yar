rule _PENightMare_v13_
{
	meta:
		description = "PENightMare v1.3"
	strings:
		$0 = {60 E9 EF 40 03 A7 07 8F 07 1C 37 5D 43 A7 04 B9 2C}
	condition:
		$0 at entrypoint
}