rule Win_Trojan_Starter_10
{
strings:
	$a0 = { 6d696428706174682c3929[0-31]28226c68772229[0-131]2e72756e28706174682b22 }

	$a1 = { 2e6578652229 }


condition:
	$a0 and $a1
}