rule Win_Trojan_Lyli_1
{
strings:
	$a0 = { 21a1de013906d8017438b80057cd21890ed2018916d00133d2b9e001b440cd2133c9b80042cd21 }


condition:
	$a0
}