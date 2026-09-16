rule Win_Trojan_CSL_2
{
strings:
	$a0 = { 04813f76027450c7077602b81e008ec08cc88ed8fcbf }


condition:
	$a0
}