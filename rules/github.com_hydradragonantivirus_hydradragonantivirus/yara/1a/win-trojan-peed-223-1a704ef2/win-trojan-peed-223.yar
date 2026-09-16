rule Win_Trojan_Peed_223
{
strings:
	$a0 = { 7302ffd0b9905f010068ae??3d008b34245881c65242030089f25266ad69c0000001 }


condition:
	$a0
}