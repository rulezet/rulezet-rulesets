import "pe"
rule _Banners_font_file_
{
	meta:
		description = "Banner's font file"
	strings:
		$0 = {AB CD 00}
	condition:
		$0 at pe.entry_point
}