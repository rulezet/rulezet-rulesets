rule Win_Trojan_Trojan_206
{
strings:
	$a0 = { e90000e2feb409ba7b02cd21b80325ba6301cd21891e74028c0676 }


condition:
	$a0
}