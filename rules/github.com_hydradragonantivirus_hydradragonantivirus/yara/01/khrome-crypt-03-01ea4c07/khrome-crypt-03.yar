import "pe"
rule _Khrome_Crypt_03_
{
	meta:
		description = "Khrome Crypt 0.3"
	strings:
		$0 = {B9 EB 09 B8 05 FE EB FC 80 C4 3B EB F4 EB 37 90 FE DF DF DF DF DF DF DF DF DF DF DF DF DF DF FE DD 20 4B 68 72 6F 6D 65 20 43 72 79 70 74 20 DE FE DC DC DC DC DC DC DC DC DC DC DC DC DC DC FE EF 00 00 00 00 00 EB 02 66 BC D9 FF EB 02 66 BC}
	condition:
		$0 at pe.entry_point
}