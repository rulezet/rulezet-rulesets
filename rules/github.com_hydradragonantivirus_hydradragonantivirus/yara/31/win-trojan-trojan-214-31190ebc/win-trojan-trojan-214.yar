rule Win_Trojan_Trojan_214
{
strings:
	$a0 = { a5a5a5c6860c0302b41a8d96e102cd218d96d502e86500 }


condition:
	$a0
}