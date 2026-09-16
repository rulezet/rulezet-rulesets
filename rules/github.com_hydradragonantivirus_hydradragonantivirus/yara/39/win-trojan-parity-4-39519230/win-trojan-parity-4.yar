rule Win_Trojan_Parity_4
{
strings:
	$a0 = { 028b855b022d03008985b502b440bab40203d7b90300cd21 }


condition:
	$a0
}