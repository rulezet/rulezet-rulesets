rule Win_Trojan_B_64
{
strings:
	$a0 = { 1304ff364e00ff364c008f06727d8f }


condition:
	$a0
}