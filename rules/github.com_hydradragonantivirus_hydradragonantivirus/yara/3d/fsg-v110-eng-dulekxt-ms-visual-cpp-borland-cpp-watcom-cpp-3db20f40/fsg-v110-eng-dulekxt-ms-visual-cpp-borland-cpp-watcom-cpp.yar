import "pe"
rule _FSG_v110_Eng__dulekxt__MS_Visual_Cpp__Borland_Cpp__Watcom_Cpp_
{
	meta:
		description = "FSG v1.10 (Eng) -> dulek/xt -> (MS Visual C++ / Borland C++ / Watcom C++)"
	strings:
		$0 = {EB 02 C7 85 1E EB 03 CD 20 EB EB 01 EB 9C EB 01 EB EB 02 CD}
	condition:
		$0 at pe.entry_point
}