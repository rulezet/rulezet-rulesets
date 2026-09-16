import "pe"
rule _ASPack_v105b_
{
	meta:
		description = "ASPack v1.05b"
	strings:
		$0 = {90 75 ??}
	condition:
		$0 at pe.entry_point
}