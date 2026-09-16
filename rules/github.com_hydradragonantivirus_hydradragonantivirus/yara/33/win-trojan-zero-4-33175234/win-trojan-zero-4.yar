rule Win_Trojan_Zero_4
{
strings:
	$a0 = { 35b060cd21bb000126817f035a4574c0 }


condition:
	$a0
}