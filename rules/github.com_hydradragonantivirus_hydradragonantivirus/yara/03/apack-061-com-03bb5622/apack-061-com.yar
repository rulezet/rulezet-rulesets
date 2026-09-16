import "pe"
rule _aPack_061_COM_
{
	meta:
		description = "aPack 0.61 [COM]"
	strings:
		$0 = {8C C8 05 00 00 8E C0 59 8E D0 51 BE 8B 01 BF 00 01 50 57 FC B6 01 BD 6C 01 FF D5 73 4C FF D5 73 18 FF D5 73 2A BB 83 01 33 C9 FF D3 FF D3 FF D3 FF D3 8B D9 43 B1 01 EB 26 E8 3B 00 49 49 AC 8A E1 93 E8 32 00 83 FB 40 73 15 83 C1 04 EB 10 AC}
	condition:
		$0 at pe.entry_point
}