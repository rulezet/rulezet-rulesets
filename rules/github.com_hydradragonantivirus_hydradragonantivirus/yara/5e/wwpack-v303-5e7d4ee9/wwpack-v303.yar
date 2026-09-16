import "pe"
rule _WWPACK_v303_
{
	meta:
		description = "WWPACK v3.03"
	strings:
		$0 = {B8 ?? ?? 8C CA 03 D0 8C C9 81 C1 ?? ?? 51 B9 ?? ?? 51 06 06 BB ?? ?? 53}
	condition:
		$0 at pe.entry_point
}