rule Win_Trojan_Nelson_1
{
strings:
	$a0 = { 9e00cd2193b8024233c933d2b440b97100ba0001cd21b8004233c933d2b440b97100ba0001cd21 }


condition:
	$a0
}