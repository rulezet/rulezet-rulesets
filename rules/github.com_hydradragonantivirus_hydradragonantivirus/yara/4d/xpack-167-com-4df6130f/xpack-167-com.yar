import "pe"
rule _XPack_167_COM_
{
	meta:
		description = "XPack 1.67 [COM]"
	strings:
		$0 = {E9 53 00 FF FD FF FB FF F9 FF BC 03 00 8B E5 4C 4C C3}
	condition:
		$0 at pe.entry_point
}