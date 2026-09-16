rule Win_Trojan_Tongji_1
{
strings:
	$a0 = { 0e1fa00500eb02a045b95006be3400eb020000300446e2fbb8a300a30100eb02 }


condition:
	$a0
}