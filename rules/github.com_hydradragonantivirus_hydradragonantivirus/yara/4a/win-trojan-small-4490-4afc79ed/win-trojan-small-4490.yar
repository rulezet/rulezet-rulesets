rule Win_Trojan_Small_4490
{
strings:
	$a0 = { 5589e531c05089e7b8??324200abe81b000000e821000000030683c60481 }


condition:
	$a0
}