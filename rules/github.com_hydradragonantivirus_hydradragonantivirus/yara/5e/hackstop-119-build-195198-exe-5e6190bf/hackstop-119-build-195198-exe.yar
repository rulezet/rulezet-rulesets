import "pe"
rule _HackStop_119_build_195198_EXE_
{
	meta:
		description = "HackStop 1.19 build 195/198 [EXE]"
	strings:
		$0 = {50 52 E8 02 00 41 24 5A 1E 0E 1F B4 09 CD 21 1F 5A 58 56 BE EB 04 5E EB FB 9A 1E 52 B8 4D 30 CD 21 86 C4 3D D6 02 73 02 CD 20 0E 1F 56 BE EB 04 5E EB FB 9A E8 02 00 24 24 5A B4 09 CD 21 56 BE EB 04 5E EB FB 9A EB 02 D8 88 5A 1F 50 52 E8 02}
	condition:
		$0 at pe.entry_point
}