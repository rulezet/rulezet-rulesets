rule Win_Trojan_DelWin_2
{
strings:
	$a0 = { 2e636f6d0d0a64656c20433a5c57494e444f57535c77696e2e636f6d }


condition:
	$a0
}