rule Win_Trojan_DSA_2
{
strings:
	$a0 = { b401c0e406b90701ba0001cd21b8004233c999cd2158b905002bc1a37901b440ba7601cd21581f }


condition:
	$a0
}