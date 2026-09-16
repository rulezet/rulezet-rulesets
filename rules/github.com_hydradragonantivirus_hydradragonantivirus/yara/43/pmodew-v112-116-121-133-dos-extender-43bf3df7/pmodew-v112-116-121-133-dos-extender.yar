import "pe"
rule _PMODEW_v112_116_121_133_DOS_extender_
{
	meta:
		description = "PMODE/W v.1.12, 1.16, 1.21, 1.33 DOS extender"
	strings:
		$0 = {FC 16 07 BF ?? ?? 8B F7 57 B9 ?? ?? F3 A5 06 1E 07 1F 5F BE ?? ?? 06 0E A4}
	condition:
		$0 at pe.entry_point
}