rule Win_Trojan_Mybot_7236
{
strings:
	$a0 = { e3b82bfb88e9bf1dcbc68e5148dcd0b879121a47580fa1afff984c9ccd8c3b9dc0839d1ebc1dfa6f842a76aab25a742f658d6907301748229500c4ddd395c65969430d7bd1a080be2dae03ea9280 }


condition:
	$a0
}