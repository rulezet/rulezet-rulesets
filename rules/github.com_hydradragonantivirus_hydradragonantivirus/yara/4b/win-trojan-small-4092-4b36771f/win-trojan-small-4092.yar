rule Win_Trojan_Small_4092
{
strings:
	$a0 = { 7402cd2be83d000000c21000e842 }


condition:
	$a0
}