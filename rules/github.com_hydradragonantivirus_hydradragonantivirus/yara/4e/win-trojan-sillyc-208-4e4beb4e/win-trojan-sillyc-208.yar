rule Win_Trojan_SillyC_208
{
strings:
	$a0 = { 02cd21b4408b9e9d02b9d4018d960001cd21b80157b957048b9e9d02cd21ff869a02b43e8b }


condition:
	$a0
}