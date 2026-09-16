import "pe"
rule _AVP_Inspector_Database_
{
	meta:
		description = "AVP Inspector Database"
	strings:
		$0 = {47 68 6F 73 74 20 42 75 73 74 65 72}
	condition:
		$0 at pe.entry_point
}