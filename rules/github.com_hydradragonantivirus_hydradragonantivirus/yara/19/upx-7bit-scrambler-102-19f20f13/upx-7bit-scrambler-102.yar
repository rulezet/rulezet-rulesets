import "pe"
rule _UPX_7bit_Scrambler_102_
{
	meta:
		description = "UPX 7bit Scrambler 1.02"
	strings:
		$0 = {0F 83 FA}
	condition:
		$0 at pe.entry_point
}