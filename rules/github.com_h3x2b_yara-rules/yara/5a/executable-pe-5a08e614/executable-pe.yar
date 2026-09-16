rule executable_pe : info executable windows
{
	meta:
				description = "Detect PE executable based on MZ and PE magic"

	strings:
		$pe = "PE"

	condition:
                                uint16be(0) == 0x4d5a and
				($pe at (uint32(0x3c)))
}