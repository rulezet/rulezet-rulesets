rule Win_Trojan_Yosha_4
{
strings:
	$a0 = { fa33db8ed3bc007c8edbfbff0e1304cd12c1e0068ec05068db01b80102b90300ba8000cd13cb }


condition:
	$a0
}