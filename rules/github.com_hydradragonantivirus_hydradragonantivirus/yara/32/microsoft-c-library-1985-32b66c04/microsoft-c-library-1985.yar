import "pe"
rule _Microsoft_C_Library_1985_
{
	meta:
		description = "Microsoft C Library 1985"
	strings:
		$0 = {BF ?? ?? 8B 36 ?? ?? 2B F7 81 FE ?? ?? 72 ?? BE ?? ?? FA 8E D7 81 C4 ?? ?? FB 73}
	condition:
		$0 at pe.entry_point
}