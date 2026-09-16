rule Win_Trojan_Leech_3
{
strings:
	$a0 = { 02e8d9028b5710b419cd21b90200cd26 }


condition:
	$a0
}