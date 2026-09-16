import "pe"
rule _EncryptPE_V22008618__WFS_
{
	meta:
		description = "EncryptPE V2.2008.6.18 -> WFS"
	strings:
		$0 = {68 ?? ?? ?? 00 E8 52 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 47 65 74 54 65 6D 70 50 61 74 68 41 00 43 72 65 61 74 65}
	condition:
		$0 at pe.entry_point
}