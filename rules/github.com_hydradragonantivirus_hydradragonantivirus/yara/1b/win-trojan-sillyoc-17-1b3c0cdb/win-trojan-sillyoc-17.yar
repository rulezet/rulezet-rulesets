rule Win_Trojan_SillyOC_17
{
strings:
	$a0 = { 68817c1aad007261b8003d8d541ecd2193b43fb90400ba }


condition:
	$a0
}