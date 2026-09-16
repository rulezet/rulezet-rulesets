rule Win_Trojan_Mayak_1
{
strings:
	$a0 = { 8ed8c4060c002e898433092e8c8435 }


condition:
	$a0
}