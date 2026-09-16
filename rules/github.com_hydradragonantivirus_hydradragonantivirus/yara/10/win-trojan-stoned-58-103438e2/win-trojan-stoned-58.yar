rule Win_Trojan_Stoned_58
{
strings:
	$a0 = { bb0002b90100b600cd1333f6bf0002b96400f3a7e329b80103b90700cd13bebe03bfbe01b9 }


condition:
	$a0
}