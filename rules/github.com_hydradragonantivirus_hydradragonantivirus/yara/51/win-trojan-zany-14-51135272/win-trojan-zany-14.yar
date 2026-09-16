rule Win_Trojan_Zany_14
{
strings:
	$a0 = { e800005b81eb0b018bebb41aba81f8cd218db6af01bf000157a4a5b44e2bc98d96a901cd21 }


condition:
	$a0
}