import "pe"
rule _WarWind_Save_file_
{
	meta:
		description = "WarWind Save file"
	strings:
		$0 = {57 41 52 53 41 56}
	condition:
		$0 at pe.entry_point
}