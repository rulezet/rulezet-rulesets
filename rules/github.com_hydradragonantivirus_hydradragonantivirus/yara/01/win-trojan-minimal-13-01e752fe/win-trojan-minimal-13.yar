rule Win_Trojan_Minimal_13
{
strings:
	$a0 = { 010100550000000000ffff3203000075000000040000003203 }


condition:
	$a0
}