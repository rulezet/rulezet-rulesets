rule Win_Trojan_Bomber_2
{
strings:
	$a0 = { d2b900efb43f9cfa0ee80b00c33d00 }


condition:
	$a0
}