rule Win_Trojan_LG_1
{
strings:
	$a0 = { ed033e8b869601a300013e8a869801a20201b8d0f1cd213dadde7505b80001ffe01e8cdb4b8edb8b1e030081eb01 }


condition:
	$a0
}