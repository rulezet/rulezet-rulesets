rule Win_Trojan_Gratug_1
{
strings:
	$a0 = { b90300ba9001cd21b8024233c933d2cd21b9e201ba0000b440cd21b80057cd21b80157cd21b4 }


condition:
	$a0
}