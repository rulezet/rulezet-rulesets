rule Win_Trojan_Wonder_1
{
strings:
	$a0 = { fa2ac646fb2ec646fc45c646fd58 }


condition:
	$a0
}