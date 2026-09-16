rule Win_Adware_Screenblaze_1
{
strings:
	$a0 = { c05a59596489106870ff49008d856cfeffffba0e000000e8f845f6ff8d45f8e8cc45f6ffc3e96a3ff6ffebe08be55dc3ffffffff25000000687474703a2f2f7777772e73637265656e62 }


condition:
	$a0
}