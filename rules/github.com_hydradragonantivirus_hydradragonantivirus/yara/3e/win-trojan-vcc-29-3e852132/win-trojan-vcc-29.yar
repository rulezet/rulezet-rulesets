rule Win_Trojan_VCC_29
{
strings:
	$a0 = { 2180fa0074f788964001e80f00b440b979018d960001cd21e80100c3b933018db646018034 }


condition:
	$a0
}