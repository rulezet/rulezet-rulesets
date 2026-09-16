rule Win_Trojan_Hallo_1
{
strings:
	$a0 = { 018b16e5022bc98b1e2003b80042cd217233ba1001b90c028b1e2003b440cd2172232bc92bd2 }


condition:
	$a0
}