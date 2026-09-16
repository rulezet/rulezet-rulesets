import "pe"
rule _CipherWall_SelfExtratorDecryptor_Console_15_
{
	meta:
		description = "CipherWall Self-Extrator/Decryptor (Console) 1.5"
	strings:
		$0 = {90 61 BE 00 10 42 00 8D BE 00 00 FE FF C7 87 C0 20 02 00 0B 6E 5B 9B 57 83 CD FF EB 0E 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB 73 EF 75 09 8B 1E 83 EE FC 11 DB 73 E4}
	condition:
		$0 at pe.entry_point
}