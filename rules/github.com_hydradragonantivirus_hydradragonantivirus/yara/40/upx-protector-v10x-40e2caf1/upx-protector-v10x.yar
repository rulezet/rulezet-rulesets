import "pe"
rule _UPX_Protector_v10x_
{
	meta:
		description = "UPX Protector v1.0x"
	strings:
		$0 = {B8 B9 33 D2 EB 01 0F 56 EB 01 0F E8 03 ?? ?? ?? EB 01 0F EB 01 0F 5E EB}
	condition:
		$0 at pe.entry_point
}