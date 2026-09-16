rule Win_Trojan_Dial911_1
{
strings:
	$a0 = { 404563686f204f66660d0a4543484f204154442c54393131203e434f4d32 }


condition:
	$a0
}