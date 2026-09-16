import "pe"
rule _RobinPE_vnew__Robin_
{
	meta:
		description = "RobinPE v.new -> Robin"
	strings:
		$0 = {60 6A 00 6A 20 6A 02 6A 00 6A 03 68 00 00 00}
	condition:
		$0 at pe.entry_point
}