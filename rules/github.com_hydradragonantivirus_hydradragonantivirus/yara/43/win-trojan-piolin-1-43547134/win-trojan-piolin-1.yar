rule Win_Trojan_Piolin_1
{
strings:
	$a0 = { ba8000b90100b80703bb0002cd13fec680fe1075f1b600fec580fd5075e8cd19b91200b820b88ec0 }


condition:
	$a0
}