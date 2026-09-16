import "pe"
rule fsg13x
{
	meta:
		author = "PEiD"
		description = "FSG 1.3x -> dulek/xt"
		group = "123"
		function = "11"
	strings:
		$a0 = { E0 ?? ?? C0 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C ?? ?? ?? 4C 6F 61 64 4C 69 62 72 61 72 79 41 ?? ?? 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 }
	condition:
		$a0 at pe.entry_point
}