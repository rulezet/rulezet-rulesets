import "pe"
rule _PE_Lock_v106_
{
	meta:
		description = "PE Lock v1.06"
	strings:
		$0 = {60 E8 5D 83 ED 06 80 BD E0 04 01 0F 84}
	condition:
		$0 at pe.entry_point
}