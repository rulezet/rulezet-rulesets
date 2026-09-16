import "pe"
rule _LZEXE_v091_v100a_2_
{
	meta:
		description = "LZEXE v0.91, v1.00a (2)"
	strings:
		$0 = {BF ?? ?? 06 89 F9 0E 41 1F 8C CB 89 FE}
	condition:
		$0 at pe.entry_point
}