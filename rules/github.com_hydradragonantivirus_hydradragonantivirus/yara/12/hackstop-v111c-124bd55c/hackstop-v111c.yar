import "pe"
rule _HACKSTOP_v111c_
{
	meta:
		description = "HACKSTOP v1.11c"
	strings:
		$0 = {B4 30 CD 21 86 E0 3D ?? ?? 73 ?? B4 ?? CD 21 B0 ?? B4 4C CD 21 53 BB ?? ?? 5B EB}
	condition:
		$0 at pe.entry_point
}