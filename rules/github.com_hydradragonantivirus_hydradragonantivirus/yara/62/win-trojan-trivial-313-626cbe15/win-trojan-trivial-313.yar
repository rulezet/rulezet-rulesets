rule Win_Trojan_Trivial_313
{
strings:
	$a0 = { 1aba3701cd21b44eb90700ba3101cd21b8023dba5501cd2193b93700ba0001b440cd21b43ecd21b41aba8000cd21cd202a2e636f6d }


condition:
	$a0
}