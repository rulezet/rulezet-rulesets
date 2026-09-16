rule Win_Trojan_Spooky_8
{
strings:
	$a0 = { 1e0e0e071fe800005d81ed09018db63b028dbe3002b90400f3a5b44e8d966602b90700cd217303e9ea00b42fcd2106 }


condition:
	$a0
}