import "pe"
rule UPXShit001 : djsiba
{
	meta:
		author="_pusher_"
		date = "2015-11"
	strings:
		$a0 = { 94 BC ?? ?? ?? ?? B9 17 00 00 00 80 34 0C ?? E2 FA 94 90 90 90 FF E0 FF }
	condition:
		$a0 at pe.entry_point
}