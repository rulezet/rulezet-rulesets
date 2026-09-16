import "pe"
rule _Img_Software_Set_graphics_file_
{
	meta:
		description = "Img Software Set graphics file"
	strings:
		$0 = {53 43 4D 49 20 20 20 31 41 54}
	condition:
		$0 at pe.entry_point
}