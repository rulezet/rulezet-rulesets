rule Win_Trojan_Small_4393
{
strings:
	$a0 = { 50b8ff75400081c001000000010424e8 }


condition:
	$a0
}