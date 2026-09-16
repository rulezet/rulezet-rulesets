rule _Stranik_13_ModulaCPascal_
{
	meta:
		description = "Stranik 1.3 Modula/C/Pascal"
	strings:
		$0 = {E9 57 41 54 43 4F 4D 20 43 2F 43 2B 2B 33 32 20 52 75 6E 2D}
	condition:
		$0 at entrypoint
}