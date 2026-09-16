rule Win_Trojan_Icebox_1
{
strings:
	$a0 = { c6058074400001e81c130000c6058074 }

	$a1 = { 4772337633202c2023696365626f78 }


condition:
	$a0 and $a1
}