rule Win_Trojan_Reggie_1
{
strings:
	$a0 = { 8edba11304484889c5b106d3e08ec0b80202b550ba0000cd13061ecb }


condition:
	$a0
}