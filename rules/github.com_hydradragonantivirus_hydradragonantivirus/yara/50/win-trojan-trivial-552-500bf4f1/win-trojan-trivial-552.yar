rule Win_Trojan_Trivial_552
{
strings:
	$a0 = { b92700be????8bfeac3206????aae2f8c3 }


condition:
	$a0
}