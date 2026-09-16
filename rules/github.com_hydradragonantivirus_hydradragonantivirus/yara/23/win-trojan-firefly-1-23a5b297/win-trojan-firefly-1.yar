rule Win_Trojan_Firefly_1
{
strings:
	$a0 = { 05b9100181370000817702000083c304e2f2 }


condition:
	$a0
}