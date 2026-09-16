rule _Borland_Cpp_DLL_
{
	meta:
		description = "Borland C++ DLL"
	strings:
		$0 = {EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90}
		$1 = {EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 A1 C1 E0 02 A3}
		$2 = {EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 A1 C1 E0 02 A3}
		$3 = {C3 E9 FF 8D}
	condition:
		$0 at entrypoint or $1 at entrypoint or $2 at entrypoint or $3 at entrypoint
}