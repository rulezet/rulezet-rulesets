rule Win_Trojan_Lilith_1
{
strings:
	$a0 = { b80000bc007c8ed01607b80302bb007eb90200ba0000cd13e99601 }


condition:
	$a0
}