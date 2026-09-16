import "pe"
rule _ICE_Archive_
{
	meta:
		description = "ICE Archive"
	strings:
		$0 = {2D 6C 68 ?? 2D}
	condition:
		$0 at pe.entry_point
}