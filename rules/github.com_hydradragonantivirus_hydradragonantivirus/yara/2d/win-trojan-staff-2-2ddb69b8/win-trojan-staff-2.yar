rule Win_Trojan_Staff_2
{
strings:
	$a0 = { 0affba8f02e820ffe801ffb80057cd }


condition:
	$a0
}