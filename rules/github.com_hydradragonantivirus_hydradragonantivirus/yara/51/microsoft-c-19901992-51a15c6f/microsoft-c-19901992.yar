import "pe"
rule _Microsoft_C_19901992_
{
	meta:
		description = "Microsoft C (1990/1992)"
	strings:
		$0 = {B4 30 CD 21 3C 02 73 ?? 33 C0 06 50 CB BF ?? ?? 8B 36 ?? ?? 2B F7 81 FE ?? ?? 72 ?? BE ?? ?? FA 8E D7}
	condition:
		$0 at pe.entry_point
}