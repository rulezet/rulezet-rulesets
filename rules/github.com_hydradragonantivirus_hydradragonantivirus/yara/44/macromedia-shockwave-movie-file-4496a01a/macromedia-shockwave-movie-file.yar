import "pe"
rule _MacroMedia_ShockWave_Movie_file_
{
	meta:
		description = "MacroMedia ShockWave Movie file"
	strings:
		$0 = {46 57 53}
	condition:
		$0 at pe.entry_point
}