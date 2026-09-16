import "pe"
rule _TPACK_v05c_m2_
{
	meta:
		description = "T-PACK v0.5c -m2"
	strings:
		$0 = {68 ?? ?? FD 60 BE ?? ?? BF ?? ?? B9 ?? ?? F3 A4 8B F7 BF ?? ?? FC 46 E9 CE FD}
	condition:
		$0 at pe.entry_point
}