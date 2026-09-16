import "pe"
rule _AntiVirus_Vaccine_v103_
{
	meta:
		description = "AntiVirus Vaccine v.1.03"
	strings:
		$0 = {FA 33 DB B9 ?? ?? 0E 1F 33 F6 FC AD 35 ?? ?? 03 D8 E2}
	condition:
		$0 at pe.entry_point
}