rule Win_Trojan_PHB_1
{
strings:
	$a0 = { 93ba0001b9db10cd21b43ecd21ebd7b43bba0612cd21 }


condition:
	$a0
}