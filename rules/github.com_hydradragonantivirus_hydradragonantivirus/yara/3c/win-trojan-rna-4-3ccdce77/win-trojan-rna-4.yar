rule Win_Trojan_RNA_4
{
strings:
	$a0 = { 1c509a3f02ba00a30c0289160e02b80020509a3f02ba }


condition:
	$a0
}