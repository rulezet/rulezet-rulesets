import "pe"
rule _Symantec_WinFax_PRO_83_Coverpage_Quick_CoverPage_
{
	meta:
		description = "Symantec WinFax PRO 8.3 Coverpage Quick CoverPage"
	strings:
		$0 = {FF FF ?? ?? ?? ?? ?? 43 6F 76 65 72 44 61 74 61 62 61 73 65}
	condition:
		$0 at pe.entry_point
}