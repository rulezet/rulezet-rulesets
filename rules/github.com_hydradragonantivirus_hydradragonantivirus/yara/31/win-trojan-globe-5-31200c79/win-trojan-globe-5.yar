rule Win_Trojan_Globe_5
{
strings:
	$a0 = { c8005589e581ec00028dbe00ff165731c0509abf09c800bf40001e57b8ff00509a2b03c8008dbe00ff1657bf5d }


condition:
	$a0
}