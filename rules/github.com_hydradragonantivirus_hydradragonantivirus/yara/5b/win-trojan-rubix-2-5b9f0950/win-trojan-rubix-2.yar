rule Win_Trojan_Rubix_2
{
strings:
	$a0 = { be2d01bfa901e80100c3608bc63004463bf775f961c3 }


condition:
	$a0
}