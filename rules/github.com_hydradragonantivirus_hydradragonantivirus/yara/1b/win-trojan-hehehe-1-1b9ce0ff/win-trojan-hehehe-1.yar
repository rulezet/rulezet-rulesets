rule Win_Trojan_Hehehe_1
{
strings:
	$a0 = { 515257565455eb2b90a6aba6aba6abc0c0c0ceb7a1bbcea6afb8abceafceb8a7bcbbbdcfcfcf2a2e636f6d00e8eb }


condition:
	$a0
}