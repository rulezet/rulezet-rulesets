import "pe"
rule _Borland_Component_
{
	meta:
		description = "Borland Component"
	strings:
		$0 = {E9 ?? ?? FE FF 8D 40 00}
	condition:
		$0 at pe.entry_point
}