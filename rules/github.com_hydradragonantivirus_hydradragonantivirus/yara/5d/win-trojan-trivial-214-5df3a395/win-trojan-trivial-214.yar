rule Win_Trojan_Trivial_214
{
strings:
	$a0 = { 2d01b92700cd21721fb42fcd218bf3b8023d8d541ecd2193b440b93300ba0001cd21b44fcd2173e1cd20 }


condition:
	$a0
}