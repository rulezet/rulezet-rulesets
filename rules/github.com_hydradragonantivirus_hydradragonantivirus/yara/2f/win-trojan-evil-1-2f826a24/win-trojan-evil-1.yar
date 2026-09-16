rule Win_Trojan_Evil_1
{
strings:
	$a0 = { 0eac01b440b9010399cd217302722db80042b9000099cd21b440b90500baab01cd21 }


condition:
	$a0
}