import "pe"
rule _EXECryptor_V21X__softcompletecom_
{
	meta:
		description = "EXECryptor V2.1X -> softcomplete.com"
	strings:
		$0 = {83 C6 14 8B 55 FC E9 ?? FF FF FF}
		$1 = {E9 ?? ?? ?? ?? 66 9C 60 50 8D 88 ?? ?? ?? ?? 8D 90 04 16 ?? ?? 8B DC 8B E1}
	condition:
		$0 or $1 at pe.entry_point
}