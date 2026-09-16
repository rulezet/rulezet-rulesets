rule Win_Trojan_Haunt_1
{
strings:
	$a0 = { 1fe814ffba5bfdb97e01b440cd21b800422bc999cd21bad8feb440b90300cd21beaeffad }


condition:
	$a0
}