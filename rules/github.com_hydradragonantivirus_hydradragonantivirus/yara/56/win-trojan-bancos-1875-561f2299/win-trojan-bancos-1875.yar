rule Win_Trojan_Bancos_1875
{
strings:
	$a0 = { 7286664a1e2001e9294318e801eaecca35c0595e57eee37ee5d76cb8b08fc108f36d16e428935c031a6409db4d793436039d671e1514d1c9a06f0eace88222eacfcfcccb70bb }


condition:
	$a0
}