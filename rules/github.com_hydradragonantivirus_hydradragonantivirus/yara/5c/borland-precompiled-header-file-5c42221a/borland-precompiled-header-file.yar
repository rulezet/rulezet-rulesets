import "pe"
rule _Borland_precompiled_header_file_
{
	meta:
		description = "Borland precompiled header file"
	strings:
		$0 = {54 50 53}
	condition:
		$0 at pe.entry_point
}