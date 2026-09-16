rule Win_Trojan_Minimal_9
{
strings:
	$a0 = { 010100550000000000ffff00000000ce000000040000001303 }


condition:
	$a0
}