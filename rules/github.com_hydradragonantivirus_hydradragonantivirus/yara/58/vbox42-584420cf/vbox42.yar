import "pe"
rule vbox42
{
	meta:
		author = "PEiD"
		description = "VBOX 4.2 MTE -> WeijunLi"
		group = "185"
		function = "0"
	strings:
		$a0 = { 8C E0 0B C5 8C E0 0B C4 03 C5 74 ?? 74 ?? 8B C5 }
	condition:
		$a0 at pe.entry_point
}