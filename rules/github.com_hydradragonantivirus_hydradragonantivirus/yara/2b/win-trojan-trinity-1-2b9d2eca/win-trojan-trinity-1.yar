rule Win_Trojan_Trinity_1
{
strings:
	$a0 = { db03a3fa03c6063c0200b440ba0002b9f401cd21b8004233c999cd21b440b90800baf403cd21 }


condition:
	$a0
}