import "pe"
rule _tElock_v092a_
{
	meta:
		description = "tElock v0.92a"
	strings:
		$0 = {E9 D5 E4 FF}
	condition:
		$0 at pe.entry_point
}