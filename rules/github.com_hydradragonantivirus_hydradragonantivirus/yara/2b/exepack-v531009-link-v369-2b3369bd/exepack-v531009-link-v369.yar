import "pe"
rule _EXEPACK_v531009_LINK_v369_
{
	meta:
		description = "EXEPACK v5.31.009 (LINK v3.69)"
	strings:
		$0 = {8B E8 8C C0}
	condition:
		$0 at pe.entry_point
}