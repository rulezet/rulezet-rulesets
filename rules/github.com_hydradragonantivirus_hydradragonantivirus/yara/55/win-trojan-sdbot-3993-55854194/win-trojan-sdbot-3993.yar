rule Win_Trojan_SdBot_3993
{
strings:
	$a0 = { 3a3a1efeb72e4156454e534849454c44676e63ebc419cf5c }


condition:
	$a0
}