rule Win_Trojan_Illusion_1328_1
{
strings:
	$a0 = { 307504b85505cf9380ff11749a80ff12749580ff4e74 }


condition:
	$a0
}