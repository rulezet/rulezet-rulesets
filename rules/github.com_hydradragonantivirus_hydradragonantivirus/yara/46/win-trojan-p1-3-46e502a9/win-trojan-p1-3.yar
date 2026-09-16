rule Win_Trojan_P1_3
{
strings:
	$a0 = { 03348bfe33c0ba54025233442246464a7df85931452247474979f8 }


condition:
	$a0
}