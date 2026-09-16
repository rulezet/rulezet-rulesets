rule _Borland_Pascal_v70_for_Windows_
{
	meta:
		description = "Borland Pascal v7.0 for Windows"
	strings:
		$0 = {A1 C1 A3 83 75 57 51 33 C0}
	condition:
		$0 at entrypoint
}