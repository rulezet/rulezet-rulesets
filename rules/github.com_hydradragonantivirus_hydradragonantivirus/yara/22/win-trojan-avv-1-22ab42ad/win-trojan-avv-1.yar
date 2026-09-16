rule Win_Trojan_Avv_1
{
strings:
	$a0 = { 81fe00017406baa001e880008cc80500108ec0be000133ffb9 }


condition:
	$a0
}