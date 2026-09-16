import "pe"
rule _dxp__Decrementing_1_byte_XOR_
{
	meta:
		description = "dxp - Decrementing 1 byte XOR"
	strings:
		$0 = {30 10 FE CA 48 49 ?? 85 C9 75 F5}
	condition:
		$0 at pe.entry_point
}