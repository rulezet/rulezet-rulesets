rule Win_Trojan_Bancos_1318
{
strings:
	$a0 = { bcd3657c1ba6f5c2cff503c8a85b068bf52afc615c544377beec96ab666b924e3b838de657b7031ca2bbb91a7eb14dd441ad7021bb8aa9b40164e926e2ffa33a5a429ce43d19313fb0afb744f67064dc41c140a4 }


condition:
	$a0
}