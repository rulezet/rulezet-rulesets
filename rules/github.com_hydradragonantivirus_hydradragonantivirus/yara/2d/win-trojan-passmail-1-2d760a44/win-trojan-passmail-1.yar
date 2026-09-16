rule Win_Trojan_Passmail_1
{
strings:
	$a0 = { 5068004b4000ffd38bd08d4dd4ffd6 }


condition:
	$a0
}