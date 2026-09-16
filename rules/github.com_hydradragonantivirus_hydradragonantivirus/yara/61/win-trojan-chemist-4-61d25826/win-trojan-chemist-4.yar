rule Win_Trojan_Chemist_4
{
strings:
	$a0 = { 8bf0bf0001fc8a0434cc88054647e2f6b8000150b4 }


condition:
	$a0
}