rule Win_Trojan_Swedish_1
{
strings:
	$a0 = { 072bf68bfeb90002f3a4b8f3000650cb2bc0cd132bc08ec0 }


condition:
	$a0
}