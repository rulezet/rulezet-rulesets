rule Win_Trojan_Packed_76
{
strings:
	$a0 = { 55508bc483c004c70000d0171358c390 }


condition:
	$a0
}