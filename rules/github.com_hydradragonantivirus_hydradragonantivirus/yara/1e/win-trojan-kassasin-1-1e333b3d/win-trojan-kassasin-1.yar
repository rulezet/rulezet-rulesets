rule Win_Trojan_Kassasin_1
{
strings:
	$a0 = { c450b0f086e0cd210bc07451bf611e4ffc9075fb1e }


condition:
	$a0
}