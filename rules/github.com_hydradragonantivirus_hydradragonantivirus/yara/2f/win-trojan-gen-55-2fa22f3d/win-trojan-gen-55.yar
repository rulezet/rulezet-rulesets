rule Win_Trojan_Gen_55
{
strings:
	$a0 = { ffcd213d0101743b06b8f135cd218c }


condition:
	$a0
}