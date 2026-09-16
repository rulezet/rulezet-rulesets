rule Win_Trojan_Gyorgyi_1
{
strings:
	$a0 = { eec000baeb03cd27071f2e807c1401 }


condition:
	$a0
}