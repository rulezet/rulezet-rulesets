import "pe"
rule _PC_PE_Encryptor_Alpha_preview_
{
	meta:
		description = "PC PE Encryptor Alpha preview"
	strings:
		$0 = {66 ?? 66}
	condition:
		$0 at pe.entry_point
}