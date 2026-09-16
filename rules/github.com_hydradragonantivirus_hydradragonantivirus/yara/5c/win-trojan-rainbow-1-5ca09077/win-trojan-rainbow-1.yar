rule Win_Trojan_Rainbow_1
{
strings:
	$a0 = { 5e83ee03b8ad1bcd133dedde754a90900e1f81c6d506813c4d5a740c }


condition:
	$a0
}