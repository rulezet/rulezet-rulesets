import "pe"
rule tElockv0952 : tE
{
	meta:
		author="_pusher_"
		date = "2015-11"
	strings:
		$a0 = { E9 DD E4 FF FF }
	condition:
		$a0 at pe.entry_point
}