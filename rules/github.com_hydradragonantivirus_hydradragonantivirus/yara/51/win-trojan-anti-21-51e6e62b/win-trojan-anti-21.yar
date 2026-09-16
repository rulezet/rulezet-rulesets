rule Win_Trojan_Anti_21
{
strings:
	$a0 = { b000e8c0ffb440ba00018b0e }


condition:
	$a0
}