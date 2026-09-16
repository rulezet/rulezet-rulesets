rule Win_Trojan_Small_4094
{
strings:
	$a0 = { e85a000000cd2ec20c006a006a006a006a00ff }


condition:
	$a0
}