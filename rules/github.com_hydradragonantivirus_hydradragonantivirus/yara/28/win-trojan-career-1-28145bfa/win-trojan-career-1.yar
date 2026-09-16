rule Win_Trojan_Career_1
{
strings:
	$a0 = { c5fdfeb8cdabcd217344fab82135cd21899e21028c }


condition:
	$a0
}