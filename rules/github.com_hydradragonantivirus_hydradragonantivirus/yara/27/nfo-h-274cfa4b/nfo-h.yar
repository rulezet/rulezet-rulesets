rule nfo_h
{
	meta:
		author = "PEiD"
		description = "NFO 1.x modified -> bart/CrackPL"
		group = "131"
		function = "0"
	strings:
		$a0 = { 60 9C 8D 50 }
	condition:
		$a0
}