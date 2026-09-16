rule Win_Trojan_Union_2
{
strings:
	$a0 = { cd2132ed02cebe100103f1bffb06fc061e07b91000f3a407b9fb05ba1001b440cd21e8bcffc3 }


condition:
	$a0
}