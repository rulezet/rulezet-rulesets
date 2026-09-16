import "pe"
rule _CRYPT_Version_17_c_Dismember_EXE_
{
	meta:
		description = "CRYPT Version 1.7 (c) Dismember (EXE)"
	strings:
		$0 = {0E 17 9C 58 F6 ?? ?? 74 ?? E9}
	condition:
		$0 at pe.entry_point
}