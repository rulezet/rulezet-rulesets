rule Win_Trojan_Packed_71
{
strings:
	$a0 = { 50b800????00ffd0 }

	$a1 = { 64ff35000000005159 }


condition:
	$a0 and $a1
}