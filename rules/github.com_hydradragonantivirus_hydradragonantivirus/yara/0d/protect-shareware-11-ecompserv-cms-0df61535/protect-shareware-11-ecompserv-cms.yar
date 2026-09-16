import "pe"
rule _Protect_Shareware_11__eCompserv_CMS_
{
	meta:
		description = "Protect Shareware 1.1 -> eCompserv CMS"
	strings:
		$0 = {53 00 74 00 72 00 69 00 6E 00 67 00 46 00 69 00 6C 00 65 00 49 00 6E 00 66 00 6F 00 00 00 ?? 01 00 00 01 00 30 00 34 00 30 00 39 00 30 00 34 00 42 00 30 00 00 00 34 00 ?? 00 01 00 43 00 6F 00 6D 00 70 00 61 00 6E 00 79 00 4E 00 61 00 6D 00 65 00 00 00 00}
	condition:
		$0 at pe.entry_point
}