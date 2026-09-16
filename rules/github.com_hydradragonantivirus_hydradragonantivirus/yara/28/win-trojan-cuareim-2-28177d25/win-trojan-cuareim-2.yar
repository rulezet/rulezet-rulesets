rule Win_Trojan_Cuareim_2
{
strings:
	$a0 = { 0e1f07e800008bfc368b2d909081ed07019083c402b42ccd2180fd167203e98601fcb907008db6b4028dbebb02f3a4 }


condition:
	$a0
}