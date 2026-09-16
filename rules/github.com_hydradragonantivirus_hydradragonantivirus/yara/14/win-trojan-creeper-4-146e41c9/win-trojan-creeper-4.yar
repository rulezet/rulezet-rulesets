rule Win_Trojan_Creeper_4
{
strings:
	$a0 = { c60e07cd27502d004b7425583dff4375148b4450908b }


condition:
	$a0
}