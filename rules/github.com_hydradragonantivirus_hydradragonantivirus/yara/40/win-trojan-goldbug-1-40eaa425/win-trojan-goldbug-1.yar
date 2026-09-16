rule Win_Trojan_Goldbug_1
{
strings:
	$a0 = { 4c03602e028400fb4030441c46e2f4618bc16033db8a5c02310743e2fb61b44099cdcc }


condition:
	$a0
}