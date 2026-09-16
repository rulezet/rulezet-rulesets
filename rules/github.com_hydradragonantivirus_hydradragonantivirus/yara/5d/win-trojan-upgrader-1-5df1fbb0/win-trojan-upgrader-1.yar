rule Win_Trojan_Upgrader_1
{
strings:
	$a0 = { ba0301cd21b80043ba6201cd21890e750181e1fe00b80143cd21b8023dcd21a37701b800578b1e7701cd21891671 }


condition:
	$a0
}