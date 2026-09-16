import "pe"
rule _CHECKPRG_c_1992_
{
	meta:
		description = "CHECKPRG (c) 1992"
	strings:
		$0 = {33 C0 BE ?? ?? 8B D8 B9 ?? ?? BF ?? ?? BA ?? ?? 47 4A 74}
	condition:
		$0 at pe.entry_point
}