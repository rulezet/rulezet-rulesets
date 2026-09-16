rule Win_Trojan_Ball_1
{
strings:
	$a0 = { 03003e8986c0092ac0e85400b440b905008d96bf09cd21b002e84400b440b9c5088d960501cd21 }


condition:
	$a0
}