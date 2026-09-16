import "pe"
rule _CRYPTCOM_11_
{
	meta:
		description = "CRYPTCOM 1.1"
	strings:
		$0 = {BF E1 FF 57 BE 0E 01 90 B9 1B 00 F3 A4 C3 8B 16 25 01 8B 0E 27 01 BF 00 01 57 BE 29 01 90 AD 33 C2 AB E2 FA C3}
	condition:
		$0 at pe.entry_point
}