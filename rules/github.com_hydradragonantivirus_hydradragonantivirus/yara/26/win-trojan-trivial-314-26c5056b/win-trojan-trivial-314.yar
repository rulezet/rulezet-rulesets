rule Win_Trojan_Trivial_314
{
strings:
	$a0 = { 3701cd21b44eb90700ba3101cd21b8023dba5501cd2193b440b93700ba0001cd21b43ecd21b41aba8000cd21cd202a2e636f6d }


condition:
	$a0
}