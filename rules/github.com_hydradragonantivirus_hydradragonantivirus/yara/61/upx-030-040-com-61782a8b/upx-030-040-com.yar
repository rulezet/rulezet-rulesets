import "pe"
rule _UPX_030__040_COM_
{
	meta:
		description = "UPX 0.30 - 0.40 [COM]"
	strings:
		$0 = {B9 00 00 BE 00 00 BF C0 FF BD FF FF FD F3 A4 FC F7 E1 93 87 F7 83 C6 00 57}
	condition:
		$0 at pe.entry_point
}