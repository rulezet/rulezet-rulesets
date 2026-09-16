rule UPX_293_302_LZMA_BoB
{
	meta:
		author = "PEiD"
		description = "UPX 2.93 - 3.02 [LZMA] -> Markus Oberhumer, Laszlo Molnar & John Reiser"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { 60 BE ?? ?? ?? 00 8D BE ?? ?? ?? ?? 57 89 E5 8D 9C 24 ?? ?? ?? ?? 31 C0 50 39 DC 75 FB 46 46 53 68 ?? ?? ?? ?? 57 83 C3 04 53 68 ?? ?? ?? ?? 56 83 C3 04 53 50 C7 03 03 00 02 00 90 90 90 90 90 }
	condition:
		$a0
}