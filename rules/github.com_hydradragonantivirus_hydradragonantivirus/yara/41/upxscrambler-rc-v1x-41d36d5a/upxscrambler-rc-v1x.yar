import "pe"
rule _UPXScrambler_RC_v1x_
{
	meta:
		description = "UPX-Scrambler RC v1.x"
	strings:
		$0 = {B8 43 ?? B9 15 ?? ?? ?? 80 34 08 E2 FA E9 D6 FF FF}
	condition:
		$0 at pe.entry_point
}