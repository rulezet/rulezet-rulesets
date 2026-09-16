rule Win_Trojan_Tiny_53
{
strings:
	$a0 = { 06b7004de92d0400a3b900b440b9b30033d2cd21b8004233c933d2cd21b440b90400bab700cd21 }


condition:
	$a0
}