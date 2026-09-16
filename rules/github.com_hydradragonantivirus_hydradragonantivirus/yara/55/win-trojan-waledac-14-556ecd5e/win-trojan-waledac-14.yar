rule Win_Trojan_Waledac_14
{
strings:
	$a0 = { 558bec83ec588b0d94d045008d15136a420003ca }


condition:
	$a0
}