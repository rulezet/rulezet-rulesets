rule Win_Trojan_DarkManko_1
{
strings:
	$a0 = { 47e2f6b94d018bfe83ef058b0535240089054747e2f5 }


condition:
	$a0
}