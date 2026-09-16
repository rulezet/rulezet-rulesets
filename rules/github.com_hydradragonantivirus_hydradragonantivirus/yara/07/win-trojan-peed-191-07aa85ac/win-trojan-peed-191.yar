rule Win_Trojan_Peed_191
{
strings:
	$a0 = { e8??0000005589e58b4d1881f9675418f87e078b4518ff542418c9c21400 }


condition:
	$a0
}