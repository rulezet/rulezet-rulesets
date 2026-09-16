rule Win_Trojan_Rape_5
{
strings:
	$a0 = { b98000ac3c6172063c7a77022c208844 }


condition:
	$a0
}