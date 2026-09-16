rule Win_Trojan_MouseDisable_8
{
strings:
	$a0 = { 406563686f206f66660d0a0d0a72756e646c6c3332206d6f7573652c64697361626c65 }


condition:
	$a0
}