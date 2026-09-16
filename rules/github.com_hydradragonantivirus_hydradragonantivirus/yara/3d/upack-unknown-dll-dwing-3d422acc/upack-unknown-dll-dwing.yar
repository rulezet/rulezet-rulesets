import "pe"
rule _Upack_Unknown_DLL___Dwing_
{
	meta:
		description = "Upack_Unknown (DLL ???) -> Dwing"
	strings:
		$0 = {60 E8 09 00 00 00 17 CD 00 00 E9 06 02}
	condition:
		$0 at pe.entry_point
}