rule Win_Trojan_Simbioz_1
{
strings:
	$a0 = { d2cd217224b8024233c933d2cd217219b440b94c010e1f8bd5cd21720c2ea1f400241f0407 }


condition:
	$a0
}