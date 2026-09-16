import "pe"
rule _PE_Pack_v099_
{
	meta:
		description = "PE Pack v0.99"
	strings:
		$0 = {74}
	condition:
		$0 at pe.entry_point
}