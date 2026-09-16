import "pe"
rule _UPX_124__Markus__Laszlo_
{
	meta:
		description = "UPX 1.24 -> Markus & Laszlo"
	strings:
		$0 = {31 2E 32 34 00 55 50 58}
	condition:
		$0 at pe.entry_point
}