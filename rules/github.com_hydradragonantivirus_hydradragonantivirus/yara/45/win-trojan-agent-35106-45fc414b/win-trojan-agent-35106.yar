rule Win_Trojan_Agent_35106
{
strings:
	$a0 = { 3febb39385af1eac6a172933e4e88da77a18e96a91de9400f09471b4288ea15000b9010d521594199b638bbe486e849cbdc11b3c19c8eafbadd85754 }


condition:
	$a0
}