rule Win_Trojan_Firstling_1
{
strings:
	$a0 = { 428b1ef305cd21c3b43f8b1ef305cd21c3b4408b1ef305cd21c3b90400d1e2d1e083d200e2f7 }


condition:
	$a0
}