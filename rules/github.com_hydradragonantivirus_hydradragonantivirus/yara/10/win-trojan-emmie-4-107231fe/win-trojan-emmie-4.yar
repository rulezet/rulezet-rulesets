rule Win_Trojan_Emmie_4
{
strings:
	$a0 = { 5dfa8bc4bc5111b989055b33de535aeb00 }


condition:
	$a0
}