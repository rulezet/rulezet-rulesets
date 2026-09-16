import "pe"
rule _Trivial173_by_SMTSMF_
{
	meta:
		description = "Trivial173 by SMT/SMF"
	strings:
		$0 = {EB ?? ?? 28 54 72 69 76 69 61 6C 31 37 33 20 62 79 20 53 4D 54 2F 53 4D 46 29}
	condition:
		$0 at pe.entry_point
}