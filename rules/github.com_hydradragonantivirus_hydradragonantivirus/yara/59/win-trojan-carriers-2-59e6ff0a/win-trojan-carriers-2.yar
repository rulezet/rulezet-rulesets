rule Win_Trojan_Carriers_2
{
strings:
	$a0 = { 17805fcccfc115fa061ff813107b5080dbe06aaf87c5c8c867216947f1a790902daf79c543879e9f }


condition:
	$a0
}