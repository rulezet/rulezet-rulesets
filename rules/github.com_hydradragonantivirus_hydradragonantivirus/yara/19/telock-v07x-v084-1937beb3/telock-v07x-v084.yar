import "pe"
rule _tElock_v07x__v084_
{
	meta:
		description = "tElock v0.7x - v0.84"
	strings:
		$0 = {60 E8 02 ?? ?? ?? CD 20 E8 ?? ?? ?? ?? 5E 2B C9 58 74}
	condition:
		$0 at pe.entry_point
}