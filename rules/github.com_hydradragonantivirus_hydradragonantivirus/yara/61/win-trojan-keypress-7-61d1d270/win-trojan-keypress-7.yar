rule Win_Trojan_Keypress_7
{
strings:
	$a0 = { 061fc706bd020000b81c35cd21891ee9028c06 }


condition:
	$a0
}