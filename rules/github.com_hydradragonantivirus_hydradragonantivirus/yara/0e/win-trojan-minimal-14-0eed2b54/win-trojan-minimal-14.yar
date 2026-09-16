rule Win_Trojan_Minimal_14
{
strings:
	$a0 = { 010100550001000000ffff21030000ce000000020000000903 }


condition:
	$a0
}