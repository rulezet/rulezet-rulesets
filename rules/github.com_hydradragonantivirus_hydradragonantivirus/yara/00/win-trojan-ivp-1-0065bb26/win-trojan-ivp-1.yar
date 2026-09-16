rule Win_Trojan_IVP_1
{
strings:
	$a0 = { 3f0a0d5b4956505d0a0d242a2e636f6d002a2e657865002e2e00cd200000008db674048dbea504b91c00a4e2fd8d96a5 }


condition:
	$a0
}