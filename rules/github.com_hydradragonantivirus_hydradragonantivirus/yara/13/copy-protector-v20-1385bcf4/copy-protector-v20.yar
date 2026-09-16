import "pe"
rule _Copy_Protector_v20_
{
	meta:
		description = "Copy Protector v2.0"
	strings:
		$0 = {2E A2 ?? ?? 53 51 52 1E 06 B4 ?? 1E 0E 1F BA ?? ?? CD 21 1F}
	condition:
		$0 at pe.entry_point
}