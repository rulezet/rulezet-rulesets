rule Win_Trojan_Anvil_1
{
strings:
	$a0 = { 0e000060b91b0e0000e8000000005d81ed100041008db50000410083c62680360046e2fa }


condition:
	$a0
}