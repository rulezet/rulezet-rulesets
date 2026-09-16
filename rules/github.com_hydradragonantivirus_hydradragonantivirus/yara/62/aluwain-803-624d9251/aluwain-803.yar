import "pe"
rule _Aluwain_803_
{
	meta:
		description = "Aluwain 8.03"
	strings:
		$0 = {B8 00 00 50 E4 21 50 B8 00 00 8C DB 03 C3 50 B8 00 00 50 CB 50}
	condition:
		$0 at pe.entry_point
}