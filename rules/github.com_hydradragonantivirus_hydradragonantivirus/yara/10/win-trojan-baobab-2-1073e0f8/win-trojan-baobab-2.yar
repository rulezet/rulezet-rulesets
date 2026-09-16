rule Win_Trojan_Baobab_2
{
strings:
	$a0 = { 63068cc88ed8bf0000b8609f8ec0be0000bb0702268b07 }


condition:
	$a0
}