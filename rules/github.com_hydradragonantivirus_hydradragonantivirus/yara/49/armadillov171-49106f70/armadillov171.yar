import "pe"
rule Armadillov171
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 }

condition:
		$a0 at pe.entry_point
}