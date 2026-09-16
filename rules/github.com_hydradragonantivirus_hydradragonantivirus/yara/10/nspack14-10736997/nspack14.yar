import "pe"
rule NsPack14 : Liuxingping
{
	meta:
		author="malware-lu"
strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 ?? ?? 40 00 2D ?? ?? 40 00 }

condition:
		$a0 at pe.entry_point
}