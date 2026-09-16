rule Win_Trojan_Small_4495
{
strings:
	$a0 = { 5589e550545fb8??324200abe81e000000e8 }


condition:
	$a0
}