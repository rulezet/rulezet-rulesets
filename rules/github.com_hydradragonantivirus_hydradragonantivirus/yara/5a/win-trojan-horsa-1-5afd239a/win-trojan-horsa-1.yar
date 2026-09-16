rule Win_Trojan_Horsa_1
{
strings:
	$a0 = { ff8c0e9904bb9104cd26585a595b58c350535152a0a704fec8b9ffff8c0e9904bb9104cd2558 }


condition:
	$a0
}