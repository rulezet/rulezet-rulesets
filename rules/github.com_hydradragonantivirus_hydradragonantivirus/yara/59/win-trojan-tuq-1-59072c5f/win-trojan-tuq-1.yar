rule Win_Trojan_TUQ_1
{
strings:
	$a0 = { 56538cc88ed8be01012e8b0405030157 }


condition:
	$a0
}