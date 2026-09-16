import "pe"
rule _Jovian_VI_graphics_file_
{
	meta:
		description = "Jovian VI graphics file"
	strings:
		$0 = {56 49 ?? ?? ?? ?? ?? 00}
	condition:
		$0 at pe.entry_point
}