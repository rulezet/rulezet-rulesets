rule Win_Trojan_Simple_3
{
strings:
	$a0 = { 018bfeb96900ac32061601aa4983f9ff7403ebf2 }


condition:
	$a0
}