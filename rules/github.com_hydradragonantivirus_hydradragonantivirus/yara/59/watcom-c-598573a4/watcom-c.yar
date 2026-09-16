rule watcom_c
{
	meta:
		author = "PEiD"
		description = "Watcom C/C++ EXE"
		group = "17"
		function = "0"
	strings:
		$a0 = { E9 ?? ?? ?? ?? ?? ?? ?? ?? 57 41 }
	condition:
		$a0
}