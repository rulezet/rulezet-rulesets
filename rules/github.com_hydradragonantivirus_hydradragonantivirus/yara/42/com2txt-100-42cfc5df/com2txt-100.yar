import "pe"
rule _COM2TXT_100_
{
	meta:
		description = "COM2TXT 1.00"
	strings:
		$0 = {54 58 50 50 50 2D 68 68 2D 67 67 2D 63 30 50 5F 58 33 45 30 5F 5F 35 4F 31 35 30 30 50 5F 2D 78 73 2C 67 31 45 68 35 33 31 35 78 6D 50 2D 3A 70 35 50 65 50 75 0D 0A 00 00 00 00 00 00 00 00 00 00 00 00 2D 68 38 35 38 4F 50 35 36 31 2D 30 70}
	condition:
		$0 at pe.entry_point
}