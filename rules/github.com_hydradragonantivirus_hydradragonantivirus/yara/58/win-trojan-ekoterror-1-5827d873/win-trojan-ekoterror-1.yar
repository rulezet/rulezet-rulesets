rule Win_Trojan_Ekoterror_1
{
strings:
	$a0 = { fa8cc83d40007703e955010510008ed8fb8becb430cd213c037303e91b01c706 }


condition:
	$a0
}