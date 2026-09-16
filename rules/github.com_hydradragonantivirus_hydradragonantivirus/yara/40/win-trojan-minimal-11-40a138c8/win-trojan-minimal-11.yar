rule Win_Trojan_Minimal_11
{
strings:
	$a0 = { 010100550001000000ffff090300005a000000050000002b03 }


condition:
	$a0
}