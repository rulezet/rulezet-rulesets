rule Win_Trojan_PinkElephantII_1
{
strings:
	$a0 = { 26a102002d0010a3e200bfa217bedd01 }


condition:
	$a0
}