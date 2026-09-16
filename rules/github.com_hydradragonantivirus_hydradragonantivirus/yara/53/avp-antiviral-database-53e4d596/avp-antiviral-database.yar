import "pe"
rule _AVP_Antiviral_Database_
{
	meta:
		description = "AVP Antiviral Database"
	strings:
		$0 = {41 56 50 20 41 6E 74 69 76 69 72 61 6C 20 44 61 74 61 62 61 73 65}
	condition:
		$0 at pe.entry_point
}