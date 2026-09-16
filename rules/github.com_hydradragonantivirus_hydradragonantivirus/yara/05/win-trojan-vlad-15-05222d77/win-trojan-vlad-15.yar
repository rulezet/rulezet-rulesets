rule Win_Trojan_VLAD_15
{
strings:
	$a0 = { 5d81ed0301eb082a2e633f6d00d007b41abae0facd218d960b01b44eb90700cd21720beb1ee81600b44fcd217315e9 }


condition:
	$a0
}