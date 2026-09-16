rule Win_Trojan_SillyRC_10
{
strings:
	$a0 = { b800b440b9bf00cd21b8004233c933d2cd21b440b90400bab700cd215a59b80157cd21b43ecd21 }


condition:
	$a0
}