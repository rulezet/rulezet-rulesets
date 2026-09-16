import "pe"
rule _PECompact_2xx_Slim_Loader__BitSum_Technologies_
{
	meta:
		description = "PECompact 2.xx (Slim Loader) --> BitSum Technologies"
	strings:
		$0 = {B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 45 43 32 00}
	condition:
		$0 at pe.entry_point
}