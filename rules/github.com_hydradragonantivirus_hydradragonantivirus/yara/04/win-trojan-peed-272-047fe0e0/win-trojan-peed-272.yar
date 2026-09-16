rule Win_Trojan_Peed_272
{
strings:
	$a0 = { badb74a40a85f387d77300b9989a010068ae }


condition:
	$a0
}