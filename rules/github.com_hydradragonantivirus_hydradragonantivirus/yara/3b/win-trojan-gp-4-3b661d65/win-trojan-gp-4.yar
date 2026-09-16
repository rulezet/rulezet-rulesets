rule Win_Trojan_GP_4
{
strings:
	$a0 = { a48bcf33d2b440cd21720de9cd00 }


condition:
	$a0
}