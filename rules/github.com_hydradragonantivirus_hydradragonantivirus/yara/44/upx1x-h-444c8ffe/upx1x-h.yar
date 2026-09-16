import "pe"
rule upx1x_h
{
	meta:
		author = "PEiD"
		description = "UPX 0.89.6 - 1.02 / 1.05 - 2.90 modified -> Markus & Laszlo"
		group = "183"
		function = "0"
	strings:
		$a0 = { 07 8B 1E 83 EE FC 11 DB ?? ED B8 01 ?? ?? ?? 01 DB ?? 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 ?? 75 }
	condition:
		$a0 at pe.entry_point
}