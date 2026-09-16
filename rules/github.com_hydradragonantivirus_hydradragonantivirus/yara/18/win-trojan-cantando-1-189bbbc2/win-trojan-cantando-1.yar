rule Win_Trojan_Cantando_1
{
strings:
	$a0 = { 8bfc368b2d81ed4203c31e06e8efff8bfdbe0301b931038a043005d205300d4746e2f4e984fe }


condition:
	$a0
}