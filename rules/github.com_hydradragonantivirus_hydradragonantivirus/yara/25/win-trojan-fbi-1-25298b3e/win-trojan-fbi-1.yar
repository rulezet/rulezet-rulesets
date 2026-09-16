rule Win_Trojan_FBI_1
{
strings:
	$a0 = { 65204642492056697275730000000013020204050608080814150513ff16051102ffffffffffffffffffffffffff0505ffffffffffffffffffffffffffffffff0fff2302ff0fffffffff13ffff0202050f02ffffff13ff }


condition:
	$a0
}