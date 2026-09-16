rule _PEShit_
{
	meta:
		description = "PEShit"
	strings:
		$0 = {EB 01 68 60 E8 ?? ?? ?? ?? 8B 1C 24 83 C3 12 81 2B E8 B1 06 ?? FE 4B FD 82 2C 24 72 C8 46 ?? 0B E4 74 9E 75 01 C7 81 73 04 D7 7A F7 2F 81 73 19 77 ?? 43 B7 F6 C3 6B B7 ?? ?? F9 FF E3 C9 C2}
	condition:
		$0 at entrypoint
}