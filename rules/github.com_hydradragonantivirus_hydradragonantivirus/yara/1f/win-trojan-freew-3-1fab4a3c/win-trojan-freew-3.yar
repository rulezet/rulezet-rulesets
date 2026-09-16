rule Win_Trojan_Freew_3
{
strings:
	$a0 = { c907720680fe01750145b41aba0301cd21b200be0301 }


condition:
	$a0
}