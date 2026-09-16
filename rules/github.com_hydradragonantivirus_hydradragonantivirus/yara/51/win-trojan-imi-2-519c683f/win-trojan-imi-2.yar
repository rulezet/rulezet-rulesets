rule Win_Trojan_IMI_2
{
strings:
	$a0 = { 40b90006ba00009cff1e560072f1b43e8b1e54009cff1e56007200fa33c08ec02ea15a0026a390 }


condition:
	$a0
}