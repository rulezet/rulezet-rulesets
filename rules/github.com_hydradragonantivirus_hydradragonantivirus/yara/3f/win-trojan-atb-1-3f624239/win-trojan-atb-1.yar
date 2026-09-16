rule Win_Trojan_ATB_1
{
strings:
	$a0 = { 0590b440cd21b43ecd21bae1008b0e1c03f6c1017405 }


condition:
	$a0
}