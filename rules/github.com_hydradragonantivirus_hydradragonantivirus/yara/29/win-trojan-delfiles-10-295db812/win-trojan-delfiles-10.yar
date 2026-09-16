rule Win_Trojan_Delfiles_10
{
strings:
	$a0 = { 406563686f206f66662064656c7472656520633a5c }


condition:
	$a0
}