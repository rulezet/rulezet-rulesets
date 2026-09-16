rule Win_Trojan_Sov_4
{
strings:
	$a0 = { 0d02e898013c00740de8b4013c007406e8d801eb0490e8 }


condition:
	$a0
}