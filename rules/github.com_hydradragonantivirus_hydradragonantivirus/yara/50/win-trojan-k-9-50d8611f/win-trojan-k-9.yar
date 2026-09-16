rule Win_Trojan_K_9
{
strings:
	$a0 = { 8da68702061eb8adf8cd2f0e1f3daef87503e98600cd118bd8cd1233c350b203b436cd215803c13b862002 }


condition:
	$a0
}