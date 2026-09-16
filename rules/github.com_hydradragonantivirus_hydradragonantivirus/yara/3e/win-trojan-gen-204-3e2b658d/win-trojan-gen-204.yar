rule Win_Trojan_Gen_204
{
strings:
	$a0 = { a4029a0d00e0015589e5b802029acd02a40281ec0202c6067b0600c6067802008dbe00fe16578dbe00ff165731 }


condition:
	$a0
}