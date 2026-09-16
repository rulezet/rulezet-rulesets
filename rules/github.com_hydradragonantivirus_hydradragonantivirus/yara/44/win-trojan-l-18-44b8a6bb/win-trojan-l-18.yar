rule Win_Trojan_L_18
{
strings:
	$a0 = { b43232d2cd21e8b302e8cd028b5710b419cd21b90200cd265be8bd02e9cf0026810612007fff }


condition:
	$a0
}