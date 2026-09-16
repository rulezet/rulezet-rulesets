rule _Borland_Cpp_for_Win32_1999_
{
	meta:
		description = "Borland C++ for Win32 1999"
	strings:
		$0 = {EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B}
		$1 = {A1 C1 E0 02 A3 57 51 33 C0 BF B9 3B CF 76 05 2B CF FC F3 AA 59}
	condition:
		$0 at entrypoint or $1 at entrypoint
}