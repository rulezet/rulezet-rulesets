rule Win_Trojan_Waledac_29
{
strings:
	$a0 = { 558becf6d3b9222d000083f24a81ef6b4700008d054378450083eb55 }


condition:
	$a0
}