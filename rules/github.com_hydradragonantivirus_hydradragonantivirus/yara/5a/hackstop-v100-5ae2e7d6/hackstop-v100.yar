import "pe"
rule _HACKSTOP_v100_
{
	meta:
		description = "HACKSTOP v1.00"
	strings:
		$0 = {FA BD ?? ?? FF E5 6A 49 48 0C ?? E4 ?? 3F 98 3F}
	condition:
		$0 at pe.entry_point
}