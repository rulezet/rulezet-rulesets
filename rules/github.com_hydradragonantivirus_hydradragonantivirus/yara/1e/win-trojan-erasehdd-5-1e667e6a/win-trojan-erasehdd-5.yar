rule Win_Trojan_EraseHDD_5
{
strings:
	$a0 = { bb3101b90300b00ab90100ba8000b403cd137302e2f8b800b88ec0b4f433ffb9190051be3101b150acabe2fc59e2f3cd20 }


condition:
	$a0
}