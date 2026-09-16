rule Win_Trojan_DanishTiny_7
{
strings:
	$a0 = { 5351568b9ceb0481c65c01b98d0390d1e973014e }


condition:
	$a0
}