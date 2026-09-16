rule Win_Trojan_Kovter_2
{
strings:
	$a0 = { 55684c0fa447688f4a3ecd687b2ef066682b2a16db54484133f681f6007e03005633f62bcd6a1056 }


condition:
	$a0
}