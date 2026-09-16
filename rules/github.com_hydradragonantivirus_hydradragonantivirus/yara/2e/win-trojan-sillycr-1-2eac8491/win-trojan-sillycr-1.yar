rule Win_Trojan_SillyCr_1
{
strings:
	$a0 = { 2125ba3202cd211f07ebcf80fc4b75593ccc75055857f3 }


condition:
	$a0
}