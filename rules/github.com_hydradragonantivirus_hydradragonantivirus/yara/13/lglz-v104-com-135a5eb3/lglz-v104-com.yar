import "pe"
rule _LGLZ_v104_com_
{
	meta:
		description = "LGLZ v1.04 [com"
	strings:
		$0 = {BF ?? ?? 3B FC 72 19 B4 09 BA 12 01 CD 21 B4 4C CD 21}
	condition:
		$0 at pe.entry_point
}