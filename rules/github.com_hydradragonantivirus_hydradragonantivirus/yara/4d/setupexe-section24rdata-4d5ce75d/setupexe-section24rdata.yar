import "pe"
rule _setupexe_Section24rdata_
{
	meta:
		description = "setup.exe Section(2/4,.rdata)"
	strings:
		$0 = {50 32 04 00 6A 32 04 00 00 00 00 00 EE 32 04 00 0C 33 04 00 2A 33 04}
	condition:
		$0 at pe.entry_point
}