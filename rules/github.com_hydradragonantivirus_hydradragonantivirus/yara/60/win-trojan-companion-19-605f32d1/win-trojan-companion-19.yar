rule Win_Trojan_Companion_19
{
strings:
	$a0 = { cd21723ab43db0018d169502cd21722e8bd8b440b95802ba0001cd217220b43ecd21721a }


condition:
	$a0
}