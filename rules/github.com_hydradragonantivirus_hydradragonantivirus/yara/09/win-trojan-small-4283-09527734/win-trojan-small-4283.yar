rule Win_Trojan_Small_4283
{
strings:
	$a0 = { 60e8540000005050e836000000e87d000000 }


condition:
	$a0
}