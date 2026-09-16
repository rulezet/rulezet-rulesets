rule Win_Trojan_Small_4245
{
strings:
	$a0 = { 60e8000000005b6629db8d9300 }


condition:
	$a0
}