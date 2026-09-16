rule Win_Trojan_Fly_1
{
strings:
	$a0 = { 1b018a161a01b9f1039087ca280fd20f87ca43e2f5eb02 }


condition:
	$a0
}