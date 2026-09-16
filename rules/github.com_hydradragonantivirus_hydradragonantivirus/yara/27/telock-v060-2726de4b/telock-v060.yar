import "pe"
rule _tElock_v060_
{
	meta:
		description = "tElock v0.60"
	strings:
		$0 = {60 E8 BD 10 ?? ?? C3 83 E2 ?? F9 75 FA}
	condition:
		$0 at pe.entry_point
}