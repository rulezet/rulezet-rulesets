import "pe"
rule _DrHalo_or_DrGenius_Image_Graphics_format_
{
	meta:
		description = "DrHalo or DrGenius Image Graphics format"
	strings:
		$0 = {3A 03 00 00}
	condition:
		$0 at pe.entry_point
}