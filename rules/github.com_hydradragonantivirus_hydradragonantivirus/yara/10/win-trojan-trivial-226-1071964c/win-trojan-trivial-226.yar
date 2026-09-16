rule Win_Trojan_Trivial_226
{
strings:
	$a0 = { b90000ba2201b44ecd21ba9e00b43ccd2193b440ba0001b128cd21 }


condition:
	$a0
}