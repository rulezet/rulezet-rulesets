rule Win_Trojan_Nautilus_1
{
strings:
	$a0 = { ac51b104d2c8903e32862601d2c89059aa90e2ecc3 }


condition:
	$a0
}