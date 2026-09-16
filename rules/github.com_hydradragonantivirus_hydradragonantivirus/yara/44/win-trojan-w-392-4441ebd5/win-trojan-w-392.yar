rule Win_Trojan_W_392
{
strings:
	$a0 = { 03f3e880f5ffff5b5a5933ff648b7f2003c732c42285f80e41008bf203f300263006282646e2f761c300c3 }


condition:
	$a0
}