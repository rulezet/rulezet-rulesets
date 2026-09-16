rule Win_Trojan_Small_4097
{
strings:
	$a0 = { e8270000000f34e838000000c21000e80200000052c383042408ebf8b8386762 }


condition:
	$a0
}