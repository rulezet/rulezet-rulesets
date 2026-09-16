import "pe"
rule _WATCOM_CCpp_runtime_system_1995_
{
	meta:
		description = "WATCOM C/C++ runtime system 1995"
	strings:
		$0 = {53 56 57 55 8B 00 24 14 8B 00 24 18 8B 6C 24 1C 83 00 03 0F 87 00 01 00 00 89 00 2E FF 24 85}
	condition:
		$0 at pe.entry_point
}