import "pe"
rule _ActiveMARKTM_R5311140__Trymedia_
{
	meta:
		description = "ActiveMARK[TM] R5.31.1140 -> Trymedia"
	strings:
		$0 = {79 11 7F AB 9A 4A 83 B5 C9 6B 1A 48 F9 27 B4 25}
	condition:
		$0 at pe.entry_point
}