import "pe"
rule _RAZOR_1911_encruptor_
{
	meta:
		description = "RAZOR 1911 encruptor"
	strings:
		$0 = {E8 ?? ?? BF ?? ?? 3B FC 72 ?? B4 4C CD 21 BE ?? ?? B9 ?? ?? FD F3 A5 FC}
	condition:
		$0 at pe.entry_point
}