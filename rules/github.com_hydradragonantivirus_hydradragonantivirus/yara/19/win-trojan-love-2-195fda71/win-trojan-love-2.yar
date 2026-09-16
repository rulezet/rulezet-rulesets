rule Win_Trojan_Love_2
{
strings:
	$a0 = { 0100ba80038bd9b81003cd13fece79f7 }


condition:
	$a0
}