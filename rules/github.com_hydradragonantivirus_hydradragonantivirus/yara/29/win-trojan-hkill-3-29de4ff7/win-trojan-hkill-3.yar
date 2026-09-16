rule Win_Trojan_HKill_3
{
strings:
	$a0 = { 860e03686bb90040b8e5038d966e0091cd21b9004233c08bd091cd21b90040b81d00918d96fc }


condition:
	$a0
}