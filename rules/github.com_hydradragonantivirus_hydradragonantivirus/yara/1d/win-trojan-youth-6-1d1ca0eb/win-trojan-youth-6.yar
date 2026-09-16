rule Win_Trojan_Youth_6
{
strings:
	$a0 = { 8002f3a4061ffab82125ba9401cd21fbe974ffcd24cd20 }


condition:
	$a0
}