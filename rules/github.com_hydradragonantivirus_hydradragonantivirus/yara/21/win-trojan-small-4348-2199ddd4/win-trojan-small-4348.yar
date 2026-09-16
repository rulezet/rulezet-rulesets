rule Win_Trojan_Small_4348
{
strings:
	$a0 = { 31db8d837bd6faf905854547065068fc080000 }


condition:
	$a0
}