rule Win_Trojan_Keypress_6
{
strings:
	$a0 = { e86c00e82d00e83f00e812007208e8fa }


condition:
	$a0
}