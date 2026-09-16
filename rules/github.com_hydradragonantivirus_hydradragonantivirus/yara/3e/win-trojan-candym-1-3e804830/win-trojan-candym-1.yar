rule Win_Trojan_Candym_1
{
strings:
	$a0 = { 6973742e6d73064479412e2e2e5589e5b806079acd02a00081ec06078cd38ec38cdbfc8dbe00ff }


condition:
	$a0
}