rule _Borland_Cpp_
{
	meta:
		description = "Borland C++"
	strings:
		$0 = {A1 C1 E0 02}
	condition:
		$0 at entrypoint
}