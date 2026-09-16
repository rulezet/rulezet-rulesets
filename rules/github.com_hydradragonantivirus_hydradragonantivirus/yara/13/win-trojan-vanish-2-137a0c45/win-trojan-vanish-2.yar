rule Win_Trojan_Vanish_2
{
strings:
	$a0 = { 5b83ec025a3bda7404b44ccd21e800008bfc368b2d81ed140083c402bf17038d8e340087cf2e81 }


condition:
	$a0
}