rule Win_Trojan_Kot_2
{
strings:
	$a0 = { 50535152561e069c0e1f832e130402a11304b106d3e08ec033f6b9a901908a9c557c26881c }


condition:
	$a0
}