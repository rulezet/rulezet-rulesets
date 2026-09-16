rule vob5
{
	meta:
		author = "PEiD"
		description = "VOB ProtectCD 5 -> Pinnacle"
		group = "188"
		function = "0"
	strings:
		$a0 = { 36 3E 26 8A C0 60 E8 }
	condition:
		$a0
}