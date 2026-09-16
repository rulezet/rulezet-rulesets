import "pe"
rule _UPX_200__Markus__Laszlo_
{
	meta:
		description = "UPX 2.00 -> Markus & Laszlo"
	strings:
		$0 = {32 2E 30 30 00 55 50 58}
	condition:
		$0 at pe.entry_point
}