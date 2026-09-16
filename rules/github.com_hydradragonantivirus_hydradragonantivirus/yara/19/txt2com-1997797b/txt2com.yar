import "pe"
rule _TXT2COM_
{
	meta:
		description = "TXT2COM"
	strings:
		$0 = {E8 ?? ?? CD 20}
	condition:
		$0 at pe.entry_point
}