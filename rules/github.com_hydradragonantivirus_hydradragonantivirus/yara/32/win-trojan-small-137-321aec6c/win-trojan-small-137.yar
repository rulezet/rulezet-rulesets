rule Win_Trojan_Small_137
{
strings:
	$a0 = { 0e0eafb027b3188ec060a761b16cf3a48ed9740850 }


condition:
	$a0
}