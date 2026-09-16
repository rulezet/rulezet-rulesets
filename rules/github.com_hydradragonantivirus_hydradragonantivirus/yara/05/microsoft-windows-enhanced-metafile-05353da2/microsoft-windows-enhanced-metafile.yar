import "pe"
rule _Microsoft_Windows_Enhanced_Metafile_
{
	meta:
		description = "Microsoft Windows Enhanced Metafile"
	strings:
		$0 = {01 00 00 00 58}
	condition:
		$0 at pe.entry_point
}