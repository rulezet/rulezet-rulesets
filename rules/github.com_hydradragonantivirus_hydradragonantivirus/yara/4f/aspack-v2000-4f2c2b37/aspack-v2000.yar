import "pe"
rule _ASPack_v2000_
{
	meta:
		description = "ASPack v2.000"
	strings:
		$0 = {60 E8 72 05 ?? ?? EB}
	condition:
		$0 at pe.entry_point
}