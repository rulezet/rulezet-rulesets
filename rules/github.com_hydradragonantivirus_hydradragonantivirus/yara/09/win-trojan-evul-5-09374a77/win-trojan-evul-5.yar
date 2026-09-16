rule Win_Trojan_Evul_5
{
strings:
	$a0 = { b440b9e0018d960601cd21e80500b43ecd21c38db6 }


condition:
	$a0
}