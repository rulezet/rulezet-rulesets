import "pe"
rule _JDPack_
{
	meta:
		description = "JDPack"
	strings:
		$0 = {EB 66 87}
	condition:
		$0 at pe.entry_point
}