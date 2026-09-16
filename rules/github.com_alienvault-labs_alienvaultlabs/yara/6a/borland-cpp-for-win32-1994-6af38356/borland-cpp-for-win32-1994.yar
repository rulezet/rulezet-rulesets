rule _Borland_Cpp_for_Win32_1994_
{
	meta:
		description = "Borland C++ for Win32 1994"
	strings:
		$0 = {A1 C1 A3 57 51 33 C0 BF B9 3B CF}
	condition:
		$0 at entrypoint
}