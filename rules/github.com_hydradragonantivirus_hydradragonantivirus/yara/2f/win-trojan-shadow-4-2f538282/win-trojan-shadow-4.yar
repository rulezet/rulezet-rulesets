rule Win_Trojan_Shadow_4
{
strings:
	$a0 = { 571e06e800005e83ee0c902e8b542d90bb2f00902e8b0033c22e890083c30281fba6067cefeb02 }


condition:
	$a0
}