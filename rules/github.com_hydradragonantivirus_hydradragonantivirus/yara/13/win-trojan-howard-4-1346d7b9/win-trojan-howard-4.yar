rule Win_Trojan_Howard_4
{
strings:
	$a0 = { 33c98d541ef7d0cd21b8fdc2f7d0cd2193b440b903008d955104cd2132e433c0 }


condition:
	$a0
}