rule Win_Trojan_Coup_1
{
strings:
	$a0 = { 1fb90300ba8000fa8306860004832e130404b8009f8ec050fbb80602 }


condition:
	$a0
}