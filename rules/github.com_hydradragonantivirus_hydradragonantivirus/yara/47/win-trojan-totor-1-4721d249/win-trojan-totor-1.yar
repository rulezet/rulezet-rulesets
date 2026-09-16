rule Win_Trojan_Totor_1
{
strings:
	$a0 = { f1f1cd212ec706370100002e8c060b013df1f17403e97f008cc88ec08ed8b4cb }


condition:
	$a0
}