rule Win_Trojan_Anti_Christ_1
{
strings:
	$a0 = { ba2e00b8023dcd21b441cd218b4c1603 }


condition:
	$a0
}