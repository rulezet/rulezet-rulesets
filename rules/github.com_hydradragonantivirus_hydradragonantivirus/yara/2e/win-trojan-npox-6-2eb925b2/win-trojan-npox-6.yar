rule Win_Trojan_NPox_6
{
strings:
	$a0 = { 3e8a865d02b93a022e30460045e2f9c3 }


condition:
	$a0
}