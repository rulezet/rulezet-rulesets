rule Win_Trojan_DelTree_11
{
strings:
	$a0 = { 64656c7472656520633a5c2a2e2a }


condition:
	$a0
}