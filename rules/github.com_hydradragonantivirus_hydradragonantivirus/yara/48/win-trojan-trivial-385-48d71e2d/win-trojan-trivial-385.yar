rule Win_Trojan_Trivial_385
{
strings:
	$a0 = { 0156b93200c7048c35c64402b3813407c34646e2f8 }


condition:
	$a0
}