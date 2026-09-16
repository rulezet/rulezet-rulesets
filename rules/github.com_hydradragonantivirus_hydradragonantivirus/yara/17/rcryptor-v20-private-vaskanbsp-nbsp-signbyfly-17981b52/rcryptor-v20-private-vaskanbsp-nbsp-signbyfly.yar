import "pe"
rule _RCryptor_V20_Private__Vaskanbsp_nbsp_SignByfly_
{
	meta:
		description = "RCryptor V2.0 Private -> Vaska&nbsp; &nbsp;* Sign.By.fly"
	strings:
		$0 = {F7 D1 83 F1 FF 6A 00 F7 D1 83 F1 FF 81 04 24 ?? ?? ?? ?? F7 D1 83 F1 FF E8 00 00 00 00 F7 D1 83 F1 FF C3}
	condition:
		$0 at pe.entry_point
}