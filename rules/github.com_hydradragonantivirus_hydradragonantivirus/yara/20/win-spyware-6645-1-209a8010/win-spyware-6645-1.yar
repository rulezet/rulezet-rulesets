rule Win_Spyware_6645_1
{
strings:
	$a0 = { f9e8cc05000056c6670143555e81be30 }


condition:
	$a0
}