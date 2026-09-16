rule Win_Trojan_Snark_1
{
strings:
	$a0 = { 01b92000cd21b440ba0001b91303cd21e8a0fe1f5ae8 }


condition:
	$a0
}