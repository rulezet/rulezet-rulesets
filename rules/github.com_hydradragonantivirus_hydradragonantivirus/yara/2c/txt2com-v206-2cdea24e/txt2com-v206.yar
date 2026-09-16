import "pe"
rule _TXT2COM_v206_
{
	meta:
		description = "TXT2COM v2.06"
	strings:
		$0 = {8D 26 ?? ?? E8 ?? ?? B8 ?? ?? CD 21 CD 20 54 58 54 32 43 4F 4D 20}
	condition:
		$0 at pe.entry_point
}