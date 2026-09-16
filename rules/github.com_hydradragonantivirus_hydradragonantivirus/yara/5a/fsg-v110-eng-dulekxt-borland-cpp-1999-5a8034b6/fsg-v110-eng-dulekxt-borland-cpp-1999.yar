import "pe"
rule _FSG_v110_Eng__dulekxt__Borland_Cpp_1999_
{
	meta:
		description = "FSG v1.10 (Eng) -> dulek/xt -> (Borland C++ 1999)"
	strings:
		$0 = {EB 02 CD 20 2B C8 68 80 ?? ?? 00 EB 02 1E BB 5E EB 02 CD 20 68 B1 2B 6E 37 40 5B 0F B6 C9}
	condition:
		$0 at pe.entry_point
}