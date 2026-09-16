rule Win_Trojan_Scitzo_4
{
strings:
	$a0 = { 0e1fbe3321e0fb8cc88ed8b87a0e8bf0bff0ab81c778568bcf81340c084646e2f84b43eb3b90e41a0cbc4cb1c30c }


condition:
	$a0
}