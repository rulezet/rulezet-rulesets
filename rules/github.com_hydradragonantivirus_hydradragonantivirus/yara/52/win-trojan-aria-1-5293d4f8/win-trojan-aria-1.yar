rule Win_Trojan_Aria_1
{
strings:
	$a0 = { c232c6d2c8880449e3a646ebf0812e2e8c1e02120e1f33f68b160012b9e0118a0432c232c6d2c8880449e3ad46ebf0fccd }


condition:
	$a0
}