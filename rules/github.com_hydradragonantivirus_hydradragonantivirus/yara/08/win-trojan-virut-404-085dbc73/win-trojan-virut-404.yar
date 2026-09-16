rule Win_Trojan_Virut_404
{
strings:
	$a0 = { f8f5f8f8558bec87dbfce85a000000f881c26100000031f681cecc290000f8 }


condition:
	$a0
}