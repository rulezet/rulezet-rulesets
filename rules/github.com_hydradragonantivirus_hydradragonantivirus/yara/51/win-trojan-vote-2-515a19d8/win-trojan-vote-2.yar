rule Win_Trojan_Vote_2
{
strings:
	$a0 = { 8d963003cd21e8250329c08ed8813e260000c07327 }


condition:
	$a0
}