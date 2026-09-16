rule Win_Trojan_Tenbyte_1
{
strings:
	$a0 = { 0e1f8d36f704bf0001b92000f3a42e }


condition:
	$a0
}