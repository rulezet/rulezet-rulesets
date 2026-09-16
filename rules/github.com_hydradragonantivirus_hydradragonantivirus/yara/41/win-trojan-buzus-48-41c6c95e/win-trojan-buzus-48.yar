rule Win_Trojan_Buzus_48
{
strings:
	$a0 = { 558bec83c4e85333c08945e88945ecb864d14400e8d389fbff33c0556859d4440064ff30648920e828 }


condition:
	$a0
}