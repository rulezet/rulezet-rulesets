rule Win_Trojan_PCBB_10
{
strings:
	$a0 = { 9c80fc3e750e81fb01c07508bb0dd09df9ca0200 }


condition:
	$a0
}