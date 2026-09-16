rule Win_Trojan_Orrible_1
{
strings:
	$a0 = { 1105b90100ba8000bb0002cd13cd20fde8bdefbb0400bfeaa3b9ff3400e41ce887b0e8d1b3e8b4 }


condition:
	$a0
}