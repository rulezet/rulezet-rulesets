rule Win_Trojan_Tiny_39
{
strings:
	$a0 = { 33ffb04df2ae741db002e8280050b1 }


condition:
	$a0
}