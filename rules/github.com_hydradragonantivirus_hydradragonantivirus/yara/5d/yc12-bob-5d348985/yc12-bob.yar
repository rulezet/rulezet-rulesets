rule yc12_BoB
{
	meta:
		author = "PEiD"
		description = "yoda's cryptor 1.2"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED F3 1D 40 ?? B9 7B 09 ?? ?? 8D BD 3B 1E 40 ?? 8B F7 AC }
	condition:
		$a0
}