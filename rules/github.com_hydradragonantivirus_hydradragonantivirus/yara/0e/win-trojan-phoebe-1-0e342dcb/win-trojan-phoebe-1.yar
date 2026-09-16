rule Win_Trojan_Phoebe_1
{
strings:
	$a0 = { 4233c933d2cd21b4408d96c601b90300cd21b8024233c933d2cd21b4408d960301b9b309cd21 }


condition:
	$a0
}