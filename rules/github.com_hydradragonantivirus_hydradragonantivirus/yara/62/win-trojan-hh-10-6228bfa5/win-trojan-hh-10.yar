rule Win_Trojan_HH_10
{
strings:
	$a0 = { b440b94d028d960601cd21e80500b43ecd21c38db61f01b90f02803417464975f9c3 }


condition:
	$a0
}