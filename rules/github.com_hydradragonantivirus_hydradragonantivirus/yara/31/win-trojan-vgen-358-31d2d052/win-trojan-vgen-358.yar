rule Win_Trojan_VGEN_358
{
strings:
	$a0 = { 6301b80009cd21b93200510e5b81c380008ec333ffbe9801bd0001b93200e83204511e520e1fb8003cba870133c9cd }


condition:
	$a0
}