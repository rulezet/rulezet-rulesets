rule Win_Trojan_Pox_2
{
strings:
	$a0 = { 0301b94206b440e89f0272f02bc875ec8bd1b80042e891 }


condition:
	$a0
}