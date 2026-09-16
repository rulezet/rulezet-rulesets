rule Win_Trojan_G_5
{
strings:
	$a0 = { 14b9de008137422483c302e2f7aa244279c3c950245c22fa6506e9631911743664cefc0aaa9aa76c274264c10a50 }


condition:
	$a0
}