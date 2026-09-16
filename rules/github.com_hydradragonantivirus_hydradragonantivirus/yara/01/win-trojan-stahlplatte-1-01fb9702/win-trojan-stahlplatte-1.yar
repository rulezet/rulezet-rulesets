rule Win_Trojan_Stahlplatte_1
{
strings:
	$a0 = { b800428b1e8f0231c931d2cd21b4408b1e8f02b9de }


condition:
	$a0
}