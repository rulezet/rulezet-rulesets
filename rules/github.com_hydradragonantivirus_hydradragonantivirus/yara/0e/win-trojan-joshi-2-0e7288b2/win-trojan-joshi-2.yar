rule Win_Trojan_Joshi_2
{
strings:
	$a0 = { f003f8b979012bc8fcf3a675108cc0 }


condition:
	$a0
}