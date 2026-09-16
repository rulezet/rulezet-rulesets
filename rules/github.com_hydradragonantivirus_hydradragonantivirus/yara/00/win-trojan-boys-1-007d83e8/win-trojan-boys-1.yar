rule Win_Trojan_Boys_1
{
strings:
	$a0 = { 5a5283c229b8023dcd2172798bd85a }


condition:
	$a0
}