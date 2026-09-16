rule Win_Trojan_Small_4265
{
strings:
	$a0 = { e8??0000006a00e8??000000[0-200]608d5c2420 }


condition:
	$a0
}