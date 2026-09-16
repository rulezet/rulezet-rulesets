rule Win_Trojan_Small_4288
{
strings:
	$a0 = { 608b4424284885c0740c8b5c24546683cbff6643eb04 }


condition:
	$a0
}