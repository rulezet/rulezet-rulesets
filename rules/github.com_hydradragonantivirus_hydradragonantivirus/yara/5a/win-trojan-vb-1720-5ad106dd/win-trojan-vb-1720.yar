rule Win_Trojan_VB_1720
{
strings:
	$a0 = { 6f746f6c650000000001000100bc334000000000007058 }


condition:
	$a0
}