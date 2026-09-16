rule obsidium1110
{
	meta:
		author = "PEiD"
		description = "Obsidium 1.1.1.0 -> Obsidium Software"
		group = "133"
		function = "0"
	strings:
		$a0 = { EB 02 ?? ?? E8 E7 1C }
	condition:
		$a0
}