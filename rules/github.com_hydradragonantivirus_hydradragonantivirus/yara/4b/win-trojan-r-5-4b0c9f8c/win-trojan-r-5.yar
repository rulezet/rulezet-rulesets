rule Win_Trojan_R_5
{
strings:
	$a0 = { b440b976038d960601cd21e80500b43ecd21c38db62001b93703803400464975f9c3 }


condition:
	$a0
}