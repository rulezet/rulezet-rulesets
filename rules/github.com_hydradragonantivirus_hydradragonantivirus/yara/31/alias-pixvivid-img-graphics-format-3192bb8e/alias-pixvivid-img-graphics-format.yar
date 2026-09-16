rule _Alias_PIXVivid_IMG_Graphics_format_
{
	meta:
		description = "Alias PIX/Vivid IMG Graphics format"
	strings:
		$0 = {00 00 ?? ?? 00 18 ?? ?? ?? ?? 01}
	condition:
		$0 at entrypoint
}