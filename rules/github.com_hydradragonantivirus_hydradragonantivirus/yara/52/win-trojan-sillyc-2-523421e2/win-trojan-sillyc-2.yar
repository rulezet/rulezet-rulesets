rule Win_Trojan_SillyC_2
{
strings:
	$a0 = { b900003e8b960a0283c203cd21b4408d960301b90b01cd21b4408d960e023e8b8e0c02cd21 }


condition:
	$a0
}