rule Win_Trojan_Trivial_478
{
strings:
	$a0 = { 90ba523b80c44081ea073a45cd214dba42f04db888fa358ac74f81eaa4eff5cd21baa3b681f2a3b74f53 }


condition:
	$a0
}