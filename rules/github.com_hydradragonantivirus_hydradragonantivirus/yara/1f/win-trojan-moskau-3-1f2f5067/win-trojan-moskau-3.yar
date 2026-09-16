rule Win_Trojan_Moskau_3
{
strings:
	$a0 = { b94e03908bd5cd218bf581c672018cc8cd018bfc8b75 }


condition:
	$a0
}