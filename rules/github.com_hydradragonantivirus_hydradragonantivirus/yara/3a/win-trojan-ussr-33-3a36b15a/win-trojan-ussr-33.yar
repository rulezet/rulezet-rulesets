rule Win_Trojan_USSR_33
{
strings:
	$a0 = { 04b80042cd212bd28bceb440cd215a59b80157cd21 }


condition:
	$a0
}