rule Win_Trojan_XOR_1
{
strings:
	$a0 = { 8ed88ed0bc007cfbb9780181e93e00be3e0081c6007c8a1e047c301c46e2fbb8c00750b83e }


condition:
	$a0
}