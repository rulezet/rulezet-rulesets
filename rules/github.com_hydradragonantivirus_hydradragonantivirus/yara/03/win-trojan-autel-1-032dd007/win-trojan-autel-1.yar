rule Win_Trojan_Autel_1
{
strings:
	$a0 = { b80600000081c00e32c78981c0eb325d665089c389cb83c14583c182f7d031c131c9b98c08b053424a83 }


condition:
	$a0
}