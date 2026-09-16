rule Win_Trojan_Khizhnjak_37
{
strings:
	$a0 = { 0201b9000133db2e8a078887b0fe43e2f6ba0c03b92000 }


condition:
	$a0
}