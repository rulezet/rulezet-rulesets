import "pe"
rule _PcShare__v40___
{
	meta:
		description = "PcShare �ļ������� v4.0 -> �޿ɷ���"
	strings:
		$0 = {55 8B EC 6A FF 68 90 34 40 00 68 B6 28 40 00 64 A1}
	condition:
		$0 at pe.entry_point
}