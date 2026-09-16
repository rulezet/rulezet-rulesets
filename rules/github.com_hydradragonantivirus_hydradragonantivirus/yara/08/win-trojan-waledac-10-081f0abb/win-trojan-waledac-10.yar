rule Win_Trojan_Waledac_10
{
strings:
	$a0 = { 558bec81ec4002000081eab40000000915 }


condition:
	$a0
}