rule Win_Trojan_Dikshev_2
{
strings:
	$a0 = { cd213bc174df83c07050ad22e080fc4874d33c8c74cfb8ff4140998bcacd2159b440fec6cd2155 }


condition:
	$a0
}