import "pe"
rule _Turbo_Cpp_30_1990_
{
	meta:
		description = "Turbo C++ 3.0 1990"
	strings:
		$0 = {8C CA 2E 89 16 ?? ?? B4 30 CD 21 8B 2E ?? ?? 8B ?? ?? ?? 8E DA A3 ?? ?? 8C 06}
	condition:
		$0 at pe.entry_point
}