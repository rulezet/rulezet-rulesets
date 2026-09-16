import "pe"
rule _Obsidium_10069__Obsidium_Software_
{
	meta:
		description = "Obsidium 1.0.0.69 -> Obsidium Software"
	strings:
		$0 = {EB 02 ?? ?? E8 A3 1C 00 00}
	condition:
		$0 at pe.entry_point
}