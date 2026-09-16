rule Win_Trojan_Packed_41
{
strings:
	$a0 = { 665066536658665b66931e16 }

	$a1 = { 5da840000f85f1ffffff61 }


condition:
	$a0 and $a1
}