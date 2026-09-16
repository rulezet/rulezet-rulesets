rule armd25
{
	meta:
		author = "PEiD"
		description = "Armadillo 2.5x - 2.6x -> Silicon Realms Toolworks"
		group = "104"
		function = "4"
	strings:
		$a0 = { 6A ?? 8B 4D 08 51 E8 AE ?? ?? ?? 83 C4 08 25 FF ?? ?? ?? 85 C0 75 07 32 C0 E9 97 }
	condition:
		$a0
}