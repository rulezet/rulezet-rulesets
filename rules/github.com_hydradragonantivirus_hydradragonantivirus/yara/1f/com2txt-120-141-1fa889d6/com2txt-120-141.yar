import "pe"
rule _COM2TXT_120__141_
{
	meta:
		description = "COM2TXT 1.20 - 1.41"
	strings:
		$0 = {54 5F 4F 4F 57 57 33 3D 58 58 57 58 50 59 35 30 50 50 5A 35 6A 51 50 5F 2D 79 73 2C 41 31 45 61 35 79 38 35 32 63 50 34 5A 34 50 50 2D 70 56 34 30 50 2D 42 4F 75 0D 0A 00 00 00 00 00 00 00 00 00 00 00 00 35 55 71 50 57 58 2C 77 50 35 30 30}
	condition:
		$0 at pe.entry_point
}