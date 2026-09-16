rule Win_Trojan_AAV_2
{
strings:
	$a0 = { b80c02b90300ba8000cd13eb029056b430cd213c03eb01902ec6066202ffe890022e803e0f }


condition:
	$a0
}