import "pe"
rule _Kodak_Color_management_for_Windows_file_
{
	meta:
		description = "Kodak Color management for Windows file"
	strings:
		$0 = {4B 43 4D 53}
	condition:
		$0 at pe.entry_point
}