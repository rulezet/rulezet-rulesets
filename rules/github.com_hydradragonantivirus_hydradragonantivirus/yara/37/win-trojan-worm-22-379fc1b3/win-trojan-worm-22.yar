rule Win_Trojan_Worm_22
{
strings:
	$a0 = { 1f8c0691040e078a16900480faff7412fcb96d03be2301565fac2ac2aafeca4975f7 }


condition:
	$a0
}