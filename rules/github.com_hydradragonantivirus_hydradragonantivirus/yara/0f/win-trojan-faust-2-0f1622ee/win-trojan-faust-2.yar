rule Win_Trojan_Faust_2
{
strings:
	$a0 = { 42cd21720a33d2b9a00490b440cd21 }


condition:
	$a0
}