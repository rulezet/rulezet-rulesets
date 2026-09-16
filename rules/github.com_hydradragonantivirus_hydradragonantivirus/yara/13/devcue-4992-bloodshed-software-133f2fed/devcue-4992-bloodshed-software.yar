import "pe"
rule _DevCue_4992__Bloodshed_Software_
{
	meta:
		description = "Dev-Cue 4.9.9.2 -> Bloodshed Software"
	strings:
		$0 = {55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 ?? ?? ?? 00 E8 C8 FE FF FF 90 8D}
	condition:
		$0 at pe.entry_point
}