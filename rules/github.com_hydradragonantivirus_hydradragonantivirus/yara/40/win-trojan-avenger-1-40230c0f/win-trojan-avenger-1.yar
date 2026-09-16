rule Win_Trojan_Avenger_1
{
strings:
	$a0 = { 5b81eb0e005333c08ed8a113044848a31304b106d3e08ec033dbb80402e89700730633c0cd }


condition:
	$a0
}