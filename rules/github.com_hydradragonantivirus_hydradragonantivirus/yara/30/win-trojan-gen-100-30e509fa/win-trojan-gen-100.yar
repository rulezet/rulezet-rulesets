rule Win_Trojan_Gen_100
{
strings:
	$a0 = { b104d3e88cdb03c30510008ed88c06 }


condition:
	$a0
}