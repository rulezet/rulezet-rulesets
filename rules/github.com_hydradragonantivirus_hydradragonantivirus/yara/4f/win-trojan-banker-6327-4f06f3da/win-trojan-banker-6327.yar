rule Win_Trojan_Banker_6327
{
strings:
	$a0 = { 558becb8e5438a0cbbf16b32fc50e80000000058 }

	$a1 = { 47306d6170 }


condition:
	$a0 and $a1
}