import "pe"
rule _SLR_OPTLINK_
{
	meta:
		description = "SLR (OPTLINK)"
	strings:
		$0 = {BF ?? ?? 8E DF FA 8E D7 81 C4 ?? ?? FB B4 30 CD 21}
	condition:
		$0 at pe.entry_point
}