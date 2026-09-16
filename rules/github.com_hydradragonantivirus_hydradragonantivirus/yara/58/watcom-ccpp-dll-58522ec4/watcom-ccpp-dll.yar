import "pe"
rule _WATCOM_CCpp_DLL_
{
	meta:
		description = "WATCOM C/C++ DLL"
	strings:
		$0 = {53 56 57 55 8B 74 24 14 8B 7C 24 18 8B 6C 24 1C 83 FF 03 0F 87}
	condition:
		$0 at pe.entry_point
}