rule Win_Trojan_Frisk_7
{
strings:
	$a0 = { e800008bfc368b2d81ed03012e803e5901b97453b932048dbe5901ba0100 }


condition:
	$a0
}