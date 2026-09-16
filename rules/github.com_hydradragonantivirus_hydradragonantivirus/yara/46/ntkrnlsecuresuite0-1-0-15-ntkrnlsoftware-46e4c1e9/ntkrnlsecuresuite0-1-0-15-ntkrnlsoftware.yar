import "pe"
rule NTkrnlSecureSuite0_1_0_15__NTkrnlSoftware
{
	meta:
		author = "PEiD"
		description = "NTkrnl Secure Suite 0.1-0.15 -> NTkrnl Software"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 34 10 00 00 28 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 68 ?? ?? ?? ?? E8 01 00 00 00 C3 C3 }
	condition:
		$a0 at pe.entry_point
}