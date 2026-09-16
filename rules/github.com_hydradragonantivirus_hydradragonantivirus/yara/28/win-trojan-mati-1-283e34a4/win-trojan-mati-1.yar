rule Win_Trojan_Mati_1
{
strings:
	$a0 = { 16c9894fc387d1560cf4068c5f08b9b677f4cd251bc9fde1eb10d0f8c3088be9d55e0ceb5be3 }


condition:
	$a0
}