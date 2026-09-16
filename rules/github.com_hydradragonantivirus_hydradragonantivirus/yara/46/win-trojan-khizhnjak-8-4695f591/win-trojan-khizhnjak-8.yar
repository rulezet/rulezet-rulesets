rule Win_Trojan_Khizhnjak_8
{
strings:
	$a0 = { 32c0a26a02ba1001b996018b1ea802b440cd21722e33c933d28b1ea802b80042cd21721fbaa502 }


condition:
	$a0
}