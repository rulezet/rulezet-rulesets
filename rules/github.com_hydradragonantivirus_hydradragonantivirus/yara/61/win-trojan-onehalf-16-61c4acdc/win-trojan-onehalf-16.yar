rule Win_Trojan_OneHalf_16
{
strings:
	$a0 = { e965ff6321111847f5697204034a3e90bbb6083ee99dfe }


condition:
	$a0
}