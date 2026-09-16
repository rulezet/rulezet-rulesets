import "pe"
rule _PE_Diminisher_v01__Teraphy_
{
	meta:
		description = "PE Diminisher v0.1 -> Teraphy"
	strings:
		$0 = {53 51 52 56 57 55 E8 00 00 00 00 5D 8B D5 81 ED A2 30 40 00 2B 95 91 33 40 00 81 EA 0B 00 00 00 89 95 9A 33 40 00 80 BD 99 33 40 00 00 74 50 E8 02 01 00 00 8B FD 8D 9D 9A 33 40 00 8B 1B 8D 87}
	condition:
		$0 at pe.entry_point
}