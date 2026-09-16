rule Win_Trojan_Boot_9
{
strings:
	$a0 = { ff8ed7bc007c8bdc8edfb84754cd13fca113044848a31304b106d3e08ec08b }


condition:
	$a0
}