import "pe"
rule _Upack_Patch_
{
	meta:
		description = "Upack_Patch"
	strings:
		$0 = {81 3A 00 00 00 02 00 00 00 00}
	condition:
		$0 at pe.entry_point
}