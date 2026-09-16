rule Win_Trojan_Complete_1
{
strings:
	$a0 = { 04b80700ab8cc0abff2e90048cc88ed88ec033f68b }


condition:
	$a0
}