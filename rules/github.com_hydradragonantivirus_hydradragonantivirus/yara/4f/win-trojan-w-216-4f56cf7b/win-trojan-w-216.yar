rule Win_Trojan_W_216
{
strings:
	$a0 = { 8db537104000000646fec8e2f9 }


condition:
	$a0
}