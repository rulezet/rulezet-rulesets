rule Win_Trojan_Small_4174
{
strings:
	$a0 = { e815000000be800022f8c1c60fe81f00 }


condition:
	$a0
}