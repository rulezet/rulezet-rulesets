rule Win_Trojan_4096_1
{
strings:
	$a0 = { 0be8d00ae89a0ae8f60ae8b40a53 }


condition:
	$a0
}