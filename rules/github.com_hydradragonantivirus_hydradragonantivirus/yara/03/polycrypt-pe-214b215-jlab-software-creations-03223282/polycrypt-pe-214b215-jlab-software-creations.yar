import "pe"
rule _PolyCrypt_PE__214b215__JLab_Software_Creations_
{
	meta:
		description = "PolyCrypt PE - 2.1.4b/2.1.5 -> JLab Software Creations"
	strings:
		$0 = {91 8B F4 AD FE C9 80 34 08 ?? E2 FA C3 60 E8 ED FF FF FF EB}
	condition:
		$0 at pe.entry_point
}