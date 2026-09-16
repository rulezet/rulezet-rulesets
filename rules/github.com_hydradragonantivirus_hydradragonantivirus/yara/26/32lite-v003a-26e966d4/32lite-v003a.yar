import "pe"
rule _32Lite_v003a_
{
	meta:
		description = "32Lite v0.03a"
	strings:
		$0 = {60 B9 ?? BA ?? BE ?? 02 38 40 4E 75 FA 8B C2 8A 18 32 DF C0}
	condition:
		$0 at pe.entry_point
}