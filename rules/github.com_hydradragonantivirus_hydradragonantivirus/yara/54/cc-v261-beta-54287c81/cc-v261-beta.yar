import "pe"
rule _CC_v261_Beta_
{
	meta:
		description = "CC v2.61 Beta"
	strings:
		$0 = {BA ?? ?? B4 30 CD 21 3C 02 73 ?? 33 C0 06 50 CB}
	condition:
		$0 at pe.entry_point
}