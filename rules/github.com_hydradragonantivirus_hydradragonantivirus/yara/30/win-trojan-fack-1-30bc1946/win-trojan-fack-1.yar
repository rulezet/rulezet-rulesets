rule Win_Trojan_Fack_1
{
strings:
	$a0 = { 80fc4b7556601eb8023dcd210e1f93ba4702b90400b43fcd218bf2ad3d4d5a7434ad3c46742fb80242e8790050 }


condition:
	$a0
}