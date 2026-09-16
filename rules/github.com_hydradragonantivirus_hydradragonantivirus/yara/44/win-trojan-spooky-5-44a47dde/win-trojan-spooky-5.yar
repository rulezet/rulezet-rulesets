rule Win_Trojan_Spooky_5
{
strings:
	$a0 = { 4233c933d2cd21b4408d96f501b90300cd21b8024233c933d2cd21b4408d960301b91f00cd21 }


condition:
	$a0
}