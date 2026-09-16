rule Win_Trojan_Ascii_192_254_71_146_1
{
strings:
	$a0 = { 3139322e3235342e37312e313436 }


condition:
	$a0
}