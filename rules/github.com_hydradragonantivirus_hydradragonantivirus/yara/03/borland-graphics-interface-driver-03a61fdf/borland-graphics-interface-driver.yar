import "pe"
rule _Borland_Graphics_Interface_Driver_
{
	meta:
		description = "Borland Graphics Interface Driver"
	strings:
		$0 = {46 42 47 44}
	condition:
		$0 at pe.entry_point
}