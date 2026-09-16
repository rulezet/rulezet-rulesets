rule Win_Trojan_Hide_2
{
strings:
	$a0 = { ffd8ffe0?0104a464946 }

	$a1 = { 3c3f706870(0d|20|0a) }


condition:
	$a0 and $a1
}