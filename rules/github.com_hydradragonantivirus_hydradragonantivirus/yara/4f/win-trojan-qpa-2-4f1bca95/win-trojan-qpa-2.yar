rule Win_Trojan_Qpa_2
{
strings:
	$a0 = { 40cd213bc172b9b43ecd2172b35b33c933d2b80042cd2172a7c60616015aba0001b440b94d0190 }


condition:
	$a0
}