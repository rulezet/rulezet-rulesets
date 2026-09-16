import "pe"
rule _tElock_v098b1__tHE_EGOiSTE_
{
	meta:
		description = "tElock v0.98b1 -> tHE EGOiSTE"
	strings:
		$0 = {E9 25 E4 FF FF}
	condition:
		$0 at pe.entry_point
}