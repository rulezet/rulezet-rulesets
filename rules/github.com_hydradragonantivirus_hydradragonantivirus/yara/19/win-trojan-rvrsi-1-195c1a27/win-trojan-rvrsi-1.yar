rule Win_Trojan_Rvrsi_1
{
strings:
	$a0 = { 56c70469cfc64402c6b95c11be00018034d746e2fa31f631c9c3 }


condition:
	$a0
}