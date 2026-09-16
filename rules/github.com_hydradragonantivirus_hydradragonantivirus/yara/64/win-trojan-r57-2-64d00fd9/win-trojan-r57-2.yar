rule Win_Trojan_R57_2
{
strings:
	$a0 = { 2863296f646564206279203164742e77306c66 }


condition:
	$a0
}