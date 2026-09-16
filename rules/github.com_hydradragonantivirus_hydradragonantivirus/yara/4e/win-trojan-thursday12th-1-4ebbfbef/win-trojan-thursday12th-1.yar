rule Win_Trojan_Thursday12th_1
{
strings:
	$a0 = { 83f90074095156302446e2fb5e59c39c }


condition:
	$a0
}