rule Win_Trojan_K_24
{
strings:
	$a0 = { b80042cd21723dba1001b92c03908b1ee302b440cd2172 }


condition:
	$a0
}