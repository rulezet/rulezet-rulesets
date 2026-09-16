rule Win_Trojan_MacGyver_5
{
strings:
	$a0 = { 1233db2dc000b106d3e08ec0065333c033d2cd13b80902b500b1010aed7504b280b108cd137201 }


condition:
	$a0
}