rule _Winkript_v10_
{
	meta:
		description = "Winkript v1.0"
	strings:
		$0 = {FF 15 ?? B1 22 38 08 74 02 B1 20 40 80 38 ?? 74 10 38 08 74 06 40 80 38 ?? 75 F6 80 38 ?? 74 01 40 33 C9 FF}
	condition:
		$0 at entrypoint
}