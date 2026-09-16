rule Win_Trojan_Star_1
{
strings:
	$a0 = { b80040cd21721433c98bd1b80242cd21b9e601ba0001b80040cd212e8b1e0601b8003ecd21 }


condition:
	$a0
}