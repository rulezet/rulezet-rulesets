import "pe"
rule _nbuild_v10_soft_
{
	meta:
		description = "nbuild v1.0 [soft]"
	strings:
		$0 = {B9 ?? ?? BB ?? ?? C0 ?? ?? 80 ?? ?? 43 E2}
	condition:
		$0 at pe.entry_point
}