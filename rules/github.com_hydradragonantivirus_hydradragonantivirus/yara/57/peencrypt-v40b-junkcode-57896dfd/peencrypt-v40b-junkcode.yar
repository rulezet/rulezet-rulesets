import "pe"
rule _PEEncrypt_v40b_JunkCode_
{
	meta:
		description = "PEEncrypt v4.0b (JunkCode)"
	strings:
		$0 = {E8 5B 83 EB 05 EB 04 52 4E 44 21 EB 02 CD 20}
	condition:
		$0 at pe.entry_point
}