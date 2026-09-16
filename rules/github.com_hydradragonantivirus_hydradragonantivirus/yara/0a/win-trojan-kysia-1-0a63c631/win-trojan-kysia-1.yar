rule Win_Trojan_Kysia_1
{
strings:
	$a0 = { 06b8eeeecd213dabab7403e817008cc98ed9a14b048b1e4904071f8cd903c10510005053cb1e068cc88ed8b42acd21 }


condition:
	$a0
}