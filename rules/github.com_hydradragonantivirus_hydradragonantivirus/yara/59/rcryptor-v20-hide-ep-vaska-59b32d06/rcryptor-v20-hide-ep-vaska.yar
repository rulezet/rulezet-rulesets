import "pe"
rule _RCryptor_v20_Hide_EP__Vaska_
{
	meta:
		description = "RCryptor v2.0 (Hide EP) --> Vaska"
	strings:
		$0 = {F7 D1 83 F1 FF 6A 00 F7 D1 83 F1 FF 81 04 24 DC 20 ?? 00 F7 D1 83 F1 FF E8 00 00 00 00 F7 D1 83 F1 FF C3}
	condition:
		$0 at pe.entry_point
}