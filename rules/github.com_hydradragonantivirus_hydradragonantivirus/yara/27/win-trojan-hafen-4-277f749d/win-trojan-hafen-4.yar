rule Win_Trojan_Hafen_4
{
strings:
	$a0 = { 731bfe84d90406e8c9ffe8b3ffe82200e8c0ff07c7 }


condition:
	$a0
}