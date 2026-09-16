import "pe"
rule _Encapsulated_Postscript_graphics_file_v20_EPSF12_
{
	meta:
		description = "Encapsulated Postscript graphics file v2.0 EPSF-1.2"
	strings:
		$0 = {25 21 50 53 2D 41 64 6F 62 65 2D 32 2E 30 20 45 50 53 46 2D 31 2E 32}
	condition:
		$0 at pe.entry_point
}