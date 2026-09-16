import "pe"
rule _PE_Intro_v10_
{
	meta:
		description = "PE Intro v1.0"
	strings:
		$0 = {EB 03 CD 20 EB EB 01 EB 1E EB 01 EB EB 02 CD 20 9C EB 03}
	condition:
		$0 at pe.entry_point
}