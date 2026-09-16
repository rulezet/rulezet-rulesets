rule Win_Trojan_I13_27
{
strings:
	$a0 = { 0c07fb645a765e3845351084bf990d100b640071edc005384535068cbfca06100b64f0702b070bc1 }


condition:
	$a0
}