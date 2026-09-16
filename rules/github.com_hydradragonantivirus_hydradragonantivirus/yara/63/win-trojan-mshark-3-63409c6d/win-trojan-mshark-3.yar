rule Win_Trojan_Mshark_3
{
strings:
	$a0 = { 023d03d6cd217303e989008bd8b43fb90400ba150103d6 }


condition:
	$a0
}