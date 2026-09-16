rule Win_Trojan_BackForm2000_1
{
strings:
	$a0 = { 0800a13a04a33404a13c04a33604a13e04a33804f8b80022cd137203e97102c6061f08000e }


condition:
	$a0
}