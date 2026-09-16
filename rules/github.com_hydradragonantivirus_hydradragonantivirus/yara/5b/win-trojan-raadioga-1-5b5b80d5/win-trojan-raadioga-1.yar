rule Win_Trojan_Raadioga_1
{
strings:
	$a0 = { 83c7fee2f8fe4501cf1eb80835be08000e1fcd218bd6b425cd21ebfe }


condition:
	$a0
}