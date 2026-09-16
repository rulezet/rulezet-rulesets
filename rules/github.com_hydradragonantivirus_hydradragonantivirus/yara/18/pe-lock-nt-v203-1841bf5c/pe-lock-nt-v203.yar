import "pe"
rule _PE_Lock_NT_v203_
{
	meta:
		description = "PE Lock NT v2.03"
	strings:
		$0 = {EB CD CD EB EB EB EB CD E8 E9 50}
	condition:
		$0 at pe.entry_point
}