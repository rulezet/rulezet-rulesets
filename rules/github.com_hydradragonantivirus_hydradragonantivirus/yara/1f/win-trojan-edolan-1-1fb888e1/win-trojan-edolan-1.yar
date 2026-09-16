rule Win_Trojan_Edolan_1
{
strings:
	$a0 = { 0500ba2701cd2133d233c9b80242cd21b440b9400390ba0001cd21b801578b161e018b0e20 }


condition:
	$a0
}