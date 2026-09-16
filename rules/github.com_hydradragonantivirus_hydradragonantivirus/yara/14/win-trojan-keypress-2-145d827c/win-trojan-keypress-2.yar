rule Win_Trojan_Keypress_2
{
strings:
	$a0 = { 35cd21891eea028c06ec02b82135cd }


condition:
	$a0
}