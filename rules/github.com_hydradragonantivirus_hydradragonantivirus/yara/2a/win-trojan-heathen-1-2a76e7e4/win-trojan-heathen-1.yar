rule Win_Trojan_Heathen_1
{
strings:
	$a0 = { ff200500006800ffff180500009b003602100500006c }


condition:
	$a0
}