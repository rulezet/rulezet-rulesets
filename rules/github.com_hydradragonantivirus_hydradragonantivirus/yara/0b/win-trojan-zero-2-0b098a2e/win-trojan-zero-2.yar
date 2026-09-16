rule Win_Trojan_Zero_2
{
strings:
	$a0 = { 0900550001000800ffff0903000054000000040000000b03 }


condition:
	$a0
}