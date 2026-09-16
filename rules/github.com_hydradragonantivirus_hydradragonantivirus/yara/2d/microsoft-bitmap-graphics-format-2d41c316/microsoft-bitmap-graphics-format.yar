import "pe"
rule _Microsoft_Bitmap_Graphics_format_
{
	meta:
		description = "Microsoft Bitmap Graphics format"
	strings:
		$0 = {01 00 09 00}
	condition:
		$0 at pe.entry_point
}