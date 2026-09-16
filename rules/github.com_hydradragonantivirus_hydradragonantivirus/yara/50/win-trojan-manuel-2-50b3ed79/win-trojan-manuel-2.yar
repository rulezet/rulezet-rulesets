rule Win_Trojan_Manuel_2
{
strings:
	$a0 = { a675fbf8c3fc268a2547ac3c0074143ac475f75756e8 }


condition:
	$a0
}