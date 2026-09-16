import "pe"
rule _PKLite_201_
{
	meta:
		description = "PKLite 2.01"
	strings:
		$0 = {41 30 00 00 FF FF 00 00 FF FF 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FF FF 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FF 2F 00 00 FF 2F 00 00 FF 2F 00 00 FF 2F 00 00 FF 2F 00 00 FF 2F 00 00 FF 2F 00 00 FF 2F FF FF 00 00 FF FF}
	condition:
		$0 at pe.entry_point
}