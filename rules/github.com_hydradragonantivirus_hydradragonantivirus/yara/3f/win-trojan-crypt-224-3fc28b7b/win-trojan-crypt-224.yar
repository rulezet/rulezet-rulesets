rule Win_Trojan_Crypt_224
{
strings:
	$a0 = { 68d1e14300e87b20000010302408142c2034 }

	$a1 = { c204e03f654b65794c083f726561 }


condition:
	$a0 and $a1
}