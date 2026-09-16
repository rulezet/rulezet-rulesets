rule Win_Trojan_L_35
{
strings:
	$a0 = { 27fa32260601fb88279043fa81fb7803907eebfbc3 }


condition:
	$a0
}