rule Win_Trojan_V270_1
{
strings:
	$a0 = { b90b01f3a4bd2301b9e600fa87ec }


condition:
	$a0
}