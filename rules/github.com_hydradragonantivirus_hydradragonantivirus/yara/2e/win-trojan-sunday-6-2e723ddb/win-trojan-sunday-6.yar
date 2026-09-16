rule Win_Trojan_Sunday_6
{
strings:
	$a0 = { 0e1fba0003b82125cd218e063100 }


condition:
	$a0
}