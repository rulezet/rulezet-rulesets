rule Win_Trojan_Pojer_6
{
strings:
	$a0 = { 1ef55150f5e800005ef583ee0af5bb260003def52e8a945407f5b92d072e3017f543e2f9 }


condition:
	$a0
}