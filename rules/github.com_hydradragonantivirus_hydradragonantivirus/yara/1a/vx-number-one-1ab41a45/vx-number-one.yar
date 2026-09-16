import "pe"
rule _Vx_Number_One_
{
	meta:
		description = "Vx: Number One"
	strings:
		$0 = {F9 07 3C 53 6D 69 6C 65 3E E8}
	condition:
		$0 at pe.entry_point
}