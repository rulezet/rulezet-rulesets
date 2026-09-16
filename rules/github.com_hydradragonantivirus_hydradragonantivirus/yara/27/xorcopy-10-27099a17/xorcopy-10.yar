import "pe"
rule _XorCopy_10_
{
	meta:
		description = "XorCopy 1.0"
	strings:
		$0 = {B8 00 05 BB 03 01 BA 00 00 31 07 43 40 39 D3 75 F8 C6 06 00 01 E9 C6 06 01 01 00 C6 06 02 01 00 31 C0 31 DB 31 D2 E9}
	condition:
		$0 at pe.entry_point
}