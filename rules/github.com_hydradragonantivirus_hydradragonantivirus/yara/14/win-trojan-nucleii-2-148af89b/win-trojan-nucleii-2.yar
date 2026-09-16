rule Win_Trojan_Nucleii_2
{
strings:
	$a0 = { d0f6d83e32864901f6d8f6d0d0c8d0c8d0c8d0c8aae2df }


condition:
	$a0
}