rule Win_Trojan_Cuareim_1
{
strings:
	$a0 = { 079090e800008bfc368b2d909081ed09019083c402b42ccd2180fd167203e98d01fcb907008db6ce028dbed502 }


condition:
	$a0
}