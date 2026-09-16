rule Win_Trojan_Macedonia_1
{
strings:
	$a0 = { 2e894405b440b99001e870ffcd21 }


condition:
	$a0
}