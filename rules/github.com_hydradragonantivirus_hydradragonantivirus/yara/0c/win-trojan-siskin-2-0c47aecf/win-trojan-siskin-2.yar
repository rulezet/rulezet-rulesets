rule Win_Trojan_Siskin_2
{
strings:
	$a0 = { 048916c504b000e84600b440b118bac304cd50b002e838000e1fb440b9f903ba0000cd50 }


condition:
	$a0
}