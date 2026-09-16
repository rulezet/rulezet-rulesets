rule _EXECryptor_V22X__softcompletecom_
{
	meta:
		description = "EXECryptor V2.2X -> softcomplete.com"
	strings:
		$0 = {FF E0 E8 04 00 00 00 FF FF FF FF 5E C3 00}
	condition:
		$0
}