rule Win_Trojan_Tuxido_1
{
strings:
	$a0 = { 66616b6f63616e2e657865 }


condition:
	$a0
}