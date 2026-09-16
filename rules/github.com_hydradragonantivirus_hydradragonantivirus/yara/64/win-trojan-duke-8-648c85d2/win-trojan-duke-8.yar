rule Win_Trojan_Duke_8
{
strings:
	$a0 = { 756b652f534d46008dbe00ff165731c0509a58066d00bfbe2a1e57b8ff00509a0f086d00c606bc }


condition:
	$a0
}