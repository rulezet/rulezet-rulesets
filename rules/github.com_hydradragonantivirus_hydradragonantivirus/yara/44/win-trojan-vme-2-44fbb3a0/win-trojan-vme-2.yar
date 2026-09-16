rule Win_Trojan_VME_2
{
strings:
	$a0 = { be0000b90000b300301c4680c300e2f8c3 }


condition:
	$a0
}