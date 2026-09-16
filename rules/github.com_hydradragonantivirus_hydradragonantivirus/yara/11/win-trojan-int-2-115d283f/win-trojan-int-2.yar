rule Win_Trojan_INT_2
{
strings:
	$a0 = { b9ffff8bd1cd9eb43fb2538bfaf7d9cd9e }


condition:
	$a0
}