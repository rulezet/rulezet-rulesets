import "pe"
rule _PE_Crypt_102__randomkilla_and_acpizer_
{
	meta:
		description = "PE Crypt 1.02 -> random,killa and acpizer"
	strings:
		$0 = {E8 00 00 00 00 5B 83 EB 05 EB 04 52 4E 44}
	condition:
		$0 at pe.entry_point
}