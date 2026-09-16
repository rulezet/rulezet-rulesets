rule sobiga
{
	meta:
		author = "PEiD"
		description = "WARNING -> VIRUS -> W32@Sobig.A_mm"
		group = "800"
		function = "21"
	strings:
		$a0 = { E9 25 E4 FF FF ?? ?? ?? 1F 9F 84 10 1E CC 01 }
	condition:
		$a0
}