import "pe"
rule _PESHiELD_0251__ANAKiN_DaVinci_
{
	meta:
		description = "PESHiELD 0.251 -> ANAKiN [DaVinci"
	strings:
		$0 = {5D 83 ED 06 EB 02 EA 04 8D}
	condition:
		$0 at pe.entry_point
}