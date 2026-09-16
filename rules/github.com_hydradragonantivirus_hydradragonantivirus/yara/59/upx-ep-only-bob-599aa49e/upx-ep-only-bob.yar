rule UPX_EP_ONLY_BoB
{
	meta:
		author = "PEiD"
		description = "UPX 1.xx - 3.xx -> Markus Oberhumer, Laszlo Molnar & John Reiser"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? C7 87 9C ?? 01 00 01 00 67 93 57 EB 11 90 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 }
	condition:
		$a0
}