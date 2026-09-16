rule Win_Trojan_VGEN_1
{
strings:
	$a0 = { 505351520e070e1fe800005d8bce8d7234bf82ffd1e9fd57f3a58d7502fcf98d7ef2c3436f7079726967687420 }


condition:
	$a0
}