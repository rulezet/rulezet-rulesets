rule Win_Trojan_DelTree_6
{
strings:
	$a0 = { 64656c747265652f7920633a5c2a2e2a }


condition:
	$a0
}