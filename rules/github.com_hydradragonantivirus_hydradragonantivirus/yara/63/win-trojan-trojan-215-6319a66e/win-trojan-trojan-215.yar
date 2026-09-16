rule Win_Trojan_Trojan_215
{
strings:
	$a0 = { 025cb82435cd21899ecb028c86cd02b4258d96bf02 }


condition:
	$a0
}