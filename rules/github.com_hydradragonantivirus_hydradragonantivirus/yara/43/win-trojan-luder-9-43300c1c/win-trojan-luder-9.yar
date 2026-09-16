rule Win_Trojan_Luder_9
{
strings:
	$a0 = { 33??64ff??6489??33d26a105952e2fd6a448b[0-170]2e6578650000000000 }


condition:
	$a0
}