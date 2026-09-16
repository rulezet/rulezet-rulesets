import "pe"
rule nullsoft13
{
	meta:
		author = "PEiD"
		description = "Nullsoft PiMP 1.3x"
		group = "24"
		function = "0"
	strings:
		$a0 = { 55 8B EC 81 EC ?? ?? ?? ?? 56 57 6A ?? BE ?? ?? ?? ?? 59 8D BD }
	condition:
		$a0 at pe.entry_point
}