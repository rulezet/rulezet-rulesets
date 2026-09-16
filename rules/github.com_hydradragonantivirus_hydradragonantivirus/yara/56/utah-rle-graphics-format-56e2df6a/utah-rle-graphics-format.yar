rule _Utah_RLE_Graphics_format_
{
	meta:
		description = "Utah RLE Graphics format"
	strings:
		$0 = {52 CC 00 00 00 00 ?? ?? ?? ?? 09 ?? 08 ?? 08}
	condition:
		$0
}