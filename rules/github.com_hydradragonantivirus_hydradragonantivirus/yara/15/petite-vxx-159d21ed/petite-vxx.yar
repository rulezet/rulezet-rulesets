import "pe"
rule _PEtite_vxx_
{
	meta:
		description = "PEtite vx.x"
	strings:
		$0 = {E9 F5 0D 0A C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4}
	condition:
		$0 at pe.entry_point
}