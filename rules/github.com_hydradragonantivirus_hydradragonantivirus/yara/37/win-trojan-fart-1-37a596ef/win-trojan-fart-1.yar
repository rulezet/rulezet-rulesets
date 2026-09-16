rule Win_Trojan_Fart_1
{
strings:
	$a0 = { 01b9d60ee902002b03cd73cd2b56525acd0d360014eb01a246cd76491e1fcd7775ec }


condition:
	$a0
}