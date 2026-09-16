rule Win_Trojan_Mybot_8330
{
strings:
	$a0 = { b56a45dd9d115f6de0d41f7e3e521adc9da0176f1d1fede4e28472d090f59478ed3793e18fdb82b24855ecb85274e9a97e9b9ca433cbfbab4f97f0d1bdcb5b3dad5cc3c38c5ff04e99cd9240e2d8e1ec }


condition:
	$a0
}