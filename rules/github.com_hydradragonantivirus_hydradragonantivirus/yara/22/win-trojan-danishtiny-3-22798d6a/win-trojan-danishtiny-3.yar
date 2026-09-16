rule Win_Trojan_DanishTiny_3
{
strings:
	$a0 = { 0300cd21803de97407b44febdce98800b80057cd21 }


condition:
	$a0
}