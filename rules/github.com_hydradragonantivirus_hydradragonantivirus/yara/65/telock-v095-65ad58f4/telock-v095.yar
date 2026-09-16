import "pe"
rule _tElock_v095_
{
	meta:
		description = "tElock v0.95"
	strings:
		$0 = {E9 59 E4 FF}
	condition:
		$0 at pe.entry_point
}