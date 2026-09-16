rule Win_Trojan_Kuzmitch_1
{
strings:
	$a0 = { dbb915038a5466309051fd43e2f9 }


condition:
	$a0
}