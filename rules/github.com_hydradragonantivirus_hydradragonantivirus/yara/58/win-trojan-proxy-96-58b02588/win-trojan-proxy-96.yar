rule Win_Trojan_Proxy_96
{
strings:
	$a0 = { 558bec535657608bc18bca6174??????e8e90f84ffffffffb890909090b820cc05e833c033c0b877626274b8997824c2 }


condition:
	$a0
}