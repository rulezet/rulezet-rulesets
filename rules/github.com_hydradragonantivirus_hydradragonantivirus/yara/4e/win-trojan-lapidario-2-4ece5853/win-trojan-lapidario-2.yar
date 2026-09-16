rule Win_Trojan_Lapidario_2
{
strings:
	$a0 = { b02aeb02b0023e88860a048d8ed6038d8610018bf02bc83e8aa612048bfeac02c4aae2fa }


condition:
	$a0
}