rule Win_Trojan_H_4
{
strings:
	$a0 = { 5b72638ed833d2b90601b43fcd21 }


condition:
	$a0
}