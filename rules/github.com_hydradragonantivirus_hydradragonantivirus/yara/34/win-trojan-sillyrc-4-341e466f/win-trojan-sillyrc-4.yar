rule Win_Trojan_SillyRC_4
{
strings:
	$a0 = { 8e742360b80242998cc9cd21fec4a32c0261b440cd2151b800428cc999cd21b44059b602cd21 }


condition:
	$a0
}