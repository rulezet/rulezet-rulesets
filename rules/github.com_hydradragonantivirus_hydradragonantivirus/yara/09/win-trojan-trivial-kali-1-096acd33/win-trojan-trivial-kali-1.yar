rule Win_Trojan_Trivial_Kali_1
{
strings:
	$a0 = { 2f01ba0001cd21595ab80157cd21eba3cd20b409babe01cd21b09eb40333c933d2bb8b01cd13b2 }


condition:
	$a0
}