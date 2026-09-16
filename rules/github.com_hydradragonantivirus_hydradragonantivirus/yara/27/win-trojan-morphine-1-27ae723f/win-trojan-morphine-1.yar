rule Win_Trojan_Morphine_1
{
strings:
	$a0 = { f38a0d150505140ce3c80b82bf47c62a37097808c62b8f818f6c0a8cfe01cb7e0fe2c30b8af138cb }


condition:
	$a0
}