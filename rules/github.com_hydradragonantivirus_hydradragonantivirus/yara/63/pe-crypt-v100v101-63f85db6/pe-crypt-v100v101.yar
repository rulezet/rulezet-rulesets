import "pe"
rule _PE_Crypt_v100v101_
{
	meta:
		description = "PE Crypt v1.00/v1.01"
	strings:
		$0 = {E8 5B 83 EB 05 EB 04 52 4E}
	condition:
		$0 at pe.entry_point
}