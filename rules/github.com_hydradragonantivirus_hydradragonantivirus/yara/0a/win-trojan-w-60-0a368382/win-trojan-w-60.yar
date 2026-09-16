rule Win_Trojan_W_60
{
strings:
	$a0 = { e8000000005d81ed061040008db51e104000b9ac06000080360046e2fa }


condition:
	$a0
}