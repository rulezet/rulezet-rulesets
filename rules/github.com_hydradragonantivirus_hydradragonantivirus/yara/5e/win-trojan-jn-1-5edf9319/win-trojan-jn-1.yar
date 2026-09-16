rule Win_Trojan_Jn_1
{
strings:
	$a0 = { 898675053e89967305b440b995028d960001cd21b8004233c98bd1cd21b440b91a008d967105cd }


condition:
	$a0
}