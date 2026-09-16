rule Win_Trojan_Vicky_4
{
strings:
	$a0 = { 01b440eb00b9a204cd2190b801578b16af01eb008b0e }


condition:
	$a0
}