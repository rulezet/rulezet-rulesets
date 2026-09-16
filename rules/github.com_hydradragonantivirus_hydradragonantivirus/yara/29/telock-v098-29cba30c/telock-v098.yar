import "pe"
rule _tElock_v098_
{
	meta:
		description = "tElock v0.98"
	strings:
		$0 = {E9 25 E4 FF}
	condition:
		$0 at pe.entry_point
}