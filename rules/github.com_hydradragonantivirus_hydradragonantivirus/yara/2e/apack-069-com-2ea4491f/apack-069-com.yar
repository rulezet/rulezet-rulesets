import "pe"
rule _aPack_069_COM_
{
	meta:
		description = "aPack 0.69 [COM]"
	strings:
		$0 = {8C C8 05 00 00 8E C0 59 8E D0 51 BE A0 01 BF 00 01 50 57 FC B6 01 BD 81 01 FF D5 73 61 FF D5 73 1C FF D5 73 3F BB 98 01 33 C9 FF D3 FF D3 FF D3 FF D3 8B D9 B1 01 85 DB 75 3A 93 EB 3C E8 4C 00 49 49 75 0A 2E 8B 1E 00 01 E8 40 00 EB 26 49 AC}
	condition:
		$0 at pe.entry_point
}