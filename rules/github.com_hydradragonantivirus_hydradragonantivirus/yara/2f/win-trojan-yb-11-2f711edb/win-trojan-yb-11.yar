rule Win_Trojan_YB_11
{
strings:
	$a0 = { 023dcd21722f93b905008d949401b43fcd2172218b84c1 }


condition:
	$a0
}