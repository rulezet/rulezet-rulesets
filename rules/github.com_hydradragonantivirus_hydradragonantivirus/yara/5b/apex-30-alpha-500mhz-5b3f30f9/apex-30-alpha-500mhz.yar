rule _Apex_30_alpha__500mhz_
{
	meta:
		description = "Apex 3.0 alpha -> 500mhz"
	strings:
		$0 = {5F B9 14 00 00 00 51 BE 00 10 40 00 B9 00 ?? ?? 00 8A 07 30 06 46 E2 FB 47 59 E2 EA 68 ?? ?? ?? 00 C3}
	condition:
		$0
}