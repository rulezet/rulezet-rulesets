rule Win_Trojan_SillyC_228
{
strings:
	$a0 = { 33c9cd217305e99f008bd8b4408b9e06048d960001b98503cd217303e989008bc08b8e020489 }


condition:
	$a0
}