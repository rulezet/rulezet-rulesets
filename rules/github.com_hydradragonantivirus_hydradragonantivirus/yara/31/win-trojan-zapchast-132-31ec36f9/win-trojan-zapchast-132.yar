rule Win_Trojan_Zapchast_132
{
strings:
	$a0 = { 5c72756e202f76206d69[0-32]74252f68656c702f737663686f73742e657865 }


condition:
	$a0
}