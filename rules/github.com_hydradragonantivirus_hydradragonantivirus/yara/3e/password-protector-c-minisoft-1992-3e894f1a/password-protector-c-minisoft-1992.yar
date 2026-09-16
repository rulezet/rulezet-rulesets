import "pe"
rule _Password_Protector_c_MiniSoft_1992_
{
	meta:
		description = "Password Protector (c) MiniSoft 1992"
	strings:
		$0 = {06 0E 0E 07 1F E8 00 00 5B 83 EB 08 BA 27 01 03 D3 E8 3C 02 BA EA}
	condition:
		$0 at pe.entry_point
}