rule Win_Trojan_Internal_4
{
strings:
	$a0 = { 8cc88ed8b840008ec0fce8580480 }


condition:
	$a0
}