rule Win_Trojan_N_29
{
strings:
	$a0 = { 0c14a49d8663a34aab91a4162e4c11a5a4aa7011c533640d6c9cf23487144f12541259e4903d8052 }


condition:
	$a0
}