rule Win_Trojan_Beda_5
{
strings:
	$a0 = { 5b0e5805????8ed8b90300fcbe????0e07bf0001f3a4b8dabecd213dfec07503eb }


condition:
	$a0
}