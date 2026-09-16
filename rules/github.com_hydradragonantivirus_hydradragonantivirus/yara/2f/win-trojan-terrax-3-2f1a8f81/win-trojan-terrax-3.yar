rule Win_Trojan_TerraX_3
{
strings:
	$a0 = { 8c9c0a008c9c0e008c9c1200b404cd1a80fa18753b909090525ae54025030303d0e5402503032bd05280fe1277 }


condition:
	$a0
}