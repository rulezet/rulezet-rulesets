import "pe"
rule _CALS_Raster_graphics_format_
{
	meta:
		description = "CALS Raster graphics format"
	strings:
		$0 = {73 72 63 64 6F 63 69 64 3A 20}
	condition:
		$0 at pe.entry_point
}