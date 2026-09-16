rule Win_Trojan_B_61
{
strings:
	$a0 = { 8ed0bc007cfb8ec40668180293b80902b90250ba0000cd1372fecb }


condition:
	$a0
}