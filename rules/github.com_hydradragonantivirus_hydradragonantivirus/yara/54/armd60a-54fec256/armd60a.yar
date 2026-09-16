rule armd60a
{
	meta:
		author = "PEiD"
		description = "Armadillo 1.60a -> Silicon Realms Toolworks"
		group = "104"
		function = "4"
	strings:
		$a0 = { 55 8B EC 6A FF 68 98 71 ?? ?? 68 48 2D ?? ?? 64 A1 ?? ?? ?? ?? 50 64 89 25 ?? ?? ?? ?? 83 EC 58 }
	condition:
		$a0
}