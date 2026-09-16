rule Win_Trojan_Peed_17
{
strings:
	$a0 = { b900000000eb1e5589e5b89a??1f0433450801d089c1c9c2080089eb81c3 }


condition:
	$a0
}