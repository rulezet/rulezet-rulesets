rule Win_Trojan_IRCBot_384
{
strings:
	$a0 = { 50680cf148008b45f050e877ccffff83c4108d8d08dfffffe8b1c5ffff50b93fd54900e8a6c5ffff50684cf048008b4df051e84fccffff }


condition:
	$a0
}