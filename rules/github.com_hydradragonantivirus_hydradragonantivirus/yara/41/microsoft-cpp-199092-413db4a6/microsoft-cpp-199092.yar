import "pe"
rule _Microsoft_Cpp_199092_
{
	meta:
		description = "Microsoft C++ (1990/92)"
	strings:
		$0 = {B4 30 CD 21 3C 02 73 05 33 C0 06 50 CB BF 00 00 8B 36 02 00 2B F7 81 FE 00 10 72 03 BE 00 10 FA 8E D7 81 C4 00 00 FB 73 00 16 1F}
	condition:
		$0 at pe.entry_point
}