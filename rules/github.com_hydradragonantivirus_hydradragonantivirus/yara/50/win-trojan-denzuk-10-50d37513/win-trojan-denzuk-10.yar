rule Win_Trojan_DenZuk_10
{
strings:
	$a0 = { 1304b106d3e00e1f8ec0be007c33ffb90014fcf3a406b8000450cb32e4cd137221b80902bb007c }


condition:
	$a0
}