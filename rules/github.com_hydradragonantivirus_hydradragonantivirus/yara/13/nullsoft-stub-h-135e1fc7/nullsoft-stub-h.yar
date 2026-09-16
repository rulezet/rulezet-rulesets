rule nullsoft_stub_h
{
	meta:
		author = "PEiD"
		description = "Nullsoft PiMP stub"
		group = "24"
		function = "19"
	strings:
		$a0 = { 83 EC ?? 53 55 56 57 FF 15 ?? ?? 40 }
	condition:
		$a0
}