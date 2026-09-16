import "pe"
rule tElockv071b8 : tE
{
	meta:
		author="_pusher_"
		date = "2015-11"
	strings:
		$a0 = { 60 E8 F3 10 00 00 C3 83 }
	condition:
		$a0 at pe.entry_point
}