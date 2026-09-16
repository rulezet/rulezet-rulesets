rule Win_Trojan_Dead_4
{
strings:
	$a0 = { f3a4b440b9bd0733d2e8f4fd7303e9ce00b80042 }


condition:
	$a0
}