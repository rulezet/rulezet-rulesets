import "pe"
rule _NetSafe_ZIPProt_
{
	meta:
		description = "NetSafe ZIP-Prot"
	strings:
		$0 = {FA 5A 86 C6 EE 86 C6 8B EC 8B 5E FA 4B 5F 4B 83 EC 06 75 01 83 8E DB E4 21 8B F3 80 CB 0E 0C 02 13 37 73 01 C5 8F 07 E6 21 2B 7E FE 8B 6F FE 7D 01 83 80 E3 FD 73 02 C5 C5 89 3F CC EA F0 FF 00 F0 CD 20 E9 9F 59 E3 06 2B F9 47 1F 47 30 25 4F}
	condition:
		$0 at pe.entry_point
}