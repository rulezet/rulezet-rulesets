rule Win_Trojan_BAT_98
{
strings:
	$a0 = { 636f7079202f62202577696e626f6f74646972 }

	$a1 = { 5c646573747265672e626174 }

	$a2 = { 5c646f7373746172742e626174 }


condition:
	$a0 and $a1 and $a2
}