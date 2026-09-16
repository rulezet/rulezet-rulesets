import "pe"
rule tElockv0982 : tE
{
	meta:
		author="_pusher_"
		date = "2015-11"
	strings:
		$a0 = { E9 1B E4 FF FF }
	condition:
		$a0 at pe.entry_point
}