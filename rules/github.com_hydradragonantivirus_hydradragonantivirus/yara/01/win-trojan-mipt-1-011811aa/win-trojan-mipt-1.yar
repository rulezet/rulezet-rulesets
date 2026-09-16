rule Win_Trojan_MIPT_1
{
strings:
	$a0 = { 8c069506b82125ba0a07cd21b81335cd21891e97 }


condition:
	$a0
}