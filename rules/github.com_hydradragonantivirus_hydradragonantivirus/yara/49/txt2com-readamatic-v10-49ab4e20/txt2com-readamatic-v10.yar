import "pe"
rule _TXT2COM_ReadAMatic_v10_
{
	meta:
		description = "TXT2COM (Read-A-Matic v1.0)"
	strings:
		$0 = {B8 ?? ?? 8E D8 8C 06 ?? ?? FA 8E D0 BC ?? ?? FB B4 ?? CD 21 A3 ?? ?? 06 50 B4 34 CD 21}
	condition:
		$0 at pe.entry_point
}