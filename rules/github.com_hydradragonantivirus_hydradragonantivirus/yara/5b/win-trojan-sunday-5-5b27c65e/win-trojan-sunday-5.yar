rule Win_Trojan_Sunday_5
{
strings:
	$a0 = { 0e1fbad202b82125cd218e063100 }


condition:
	$a0
}