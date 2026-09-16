rule NsPack14by : NorthStarLiuXingPing
{
	meta:
		author="malware-lu"
strings:
		$a0 = { 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 2D 01 13 8B 33 03 7B 04 57 51 52 53 }

condition:
		$a0
}