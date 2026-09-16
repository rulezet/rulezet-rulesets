rule Win_Trojan_Halka_4
{
strings:
	$a0 = { 0e0183c402b98d028db63a018bfeac2e2a060401eb0590b44ccd2150b80054cd2158aae2e9 }


condition:
	$a0
}