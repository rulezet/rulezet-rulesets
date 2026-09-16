rule Win_Trojan_Dialogos_2
{
strings:
	$a0 = { b440b9f205ba000103d6cd21b0018bfe28859404 }


condition:
	$a0
}