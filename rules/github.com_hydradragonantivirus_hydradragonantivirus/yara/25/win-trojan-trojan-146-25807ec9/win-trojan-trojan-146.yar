rule Win_Trojan_Trojan_146
{
strings:
	$a0 = { 060e00eb2090b80835cd212e891e1300 }


condition:
	$a0
}