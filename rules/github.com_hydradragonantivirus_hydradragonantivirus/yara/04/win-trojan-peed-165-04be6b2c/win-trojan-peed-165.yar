rule Win_Trojan_Peed_165
{
strings:
	$a0 = { 7106870283c204c37602cd03be081e3c00ff9621630400c1e00ec1e00ab9af34 }


condition:
	$a0
}