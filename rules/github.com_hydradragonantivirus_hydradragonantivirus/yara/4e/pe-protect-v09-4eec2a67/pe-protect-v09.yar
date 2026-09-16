import "pe"
rule _PE_Protect_v09_
{
	meta:
		description = "PE Protect v0.9"
	strings:
		$0 = {E8 E8 01 60 01 AD B3 27 40}
	condition:
		$0 at pe.entry_point
}