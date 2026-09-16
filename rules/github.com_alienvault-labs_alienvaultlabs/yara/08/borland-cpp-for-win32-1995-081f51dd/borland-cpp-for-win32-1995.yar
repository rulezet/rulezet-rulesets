rule _Borland_Cpp_for_Win32_1995_
{
	meta:
		description = "Borland C++ for Win32 1995"
	strings:
		$0 = {A1 C1 A3 83 75 80}
		$1 = {EB 10 66 62 3A 43 2B 2B 48 4F 4F 4B 90 E9 A1 C1 E0 02 A3}
	condition:
		$0 at entrypoint or $1 at entrypoint
}