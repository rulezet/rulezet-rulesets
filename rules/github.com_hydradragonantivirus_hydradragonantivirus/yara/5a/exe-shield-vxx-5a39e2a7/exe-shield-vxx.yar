import "pe"
rule _Exe_Shield_vxx_
{
	meta:
		description = "Exe Shield vx.x"
	strings:
		$0 = {EB 06 68 90 1F 06 ?? C3 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F}
	condition:
		$0 at pe.entry_point
}