import "pe"
rule _DIET_v102b_v110a_v120_
{
	meta:
		description = "DIET v1.02b, v1.10a, v1.20"
	strings:
		$0 = {BE ?? ?? BF ?? ?? B9 ?? ?? 3B FC 72 ?? B4 4C CD 21 FD F3 A5 FC}
	condition:
		$0 at pe.entry_point
}