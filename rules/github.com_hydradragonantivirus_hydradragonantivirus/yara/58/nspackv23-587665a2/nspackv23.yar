rule nSpackV23 : LiuXingPing
{
	meta:
		author="malware-lu"
strings:
		$a0 = { 9C 60 70 61 63 6B 24 40 }

condition:
		$a0
}