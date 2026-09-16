rule Win_Trojan_Dementia_4
{
strings:
	$a0 = { cfa2ebe7efe8c28a8bbe80c2cfaee2c3cbc3c8d2cfc7c2bcbd }


condition:
	$a0
}