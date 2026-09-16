import "pe"
rule PolyCryptPE_2_1_4b_2_1_5__JLabSoftwareCreations
{
	meta:
		author = "PEiD"
		description = "PolyCrypt PE - 2.1.4b/2.1.5 -> JLab Software Creations"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 91 8B F4 AD FE C9 80 34 08 ?? E2 FA C3 60 E8 ED FF FF FF EB }
	condition:
		$a0 at pe.entry_point
}