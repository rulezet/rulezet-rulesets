rule Win_Trojan_Katya_2
{
strings:
	$a0 = { e800005e505683c615ba????b9cd003114ade2fb }


condition:
	$a0
}