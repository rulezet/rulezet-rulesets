rule Win_Trojan_Screen_1
{
strings:
	$a0 = { 99cd218cc03d21437503e982008cd8488ec0268a1e0000 }


condition:
	$a0
}