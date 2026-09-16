rule Win_Trojan_SwedishDisaster_1
{
strings:
	$a0 = { 02bb0002b901002bd29c2eff1e0800 }


condition:
	$a0
}