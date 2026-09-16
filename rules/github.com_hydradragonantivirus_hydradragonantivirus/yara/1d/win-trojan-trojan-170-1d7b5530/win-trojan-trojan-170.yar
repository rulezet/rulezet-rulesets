rule Win_Trojan_Trojan_170
{
strings:
	$a0 = { 53e810005b90b99a02ba0001b440cd21e80100c3bb340a8a }


condition:
	$a0
}