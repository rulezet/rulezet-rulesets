rule Win_Trojan_R_4
{
strings:
	$a0 = { b440b976038d960600cd21e80500b43ecd21c38db62000b93703803400464975f9c3 }


condition:
	$a0
}