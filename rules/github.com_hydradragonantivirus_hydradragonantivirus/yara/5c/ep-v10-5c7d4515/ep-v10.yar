import "pe"
rule _EP_v10_
{
	meta:
		description = "EP v1.0"
	strings:
		$0 = {6A 60 E9 01}
	condition:
		$0 at pe.entry_point
}