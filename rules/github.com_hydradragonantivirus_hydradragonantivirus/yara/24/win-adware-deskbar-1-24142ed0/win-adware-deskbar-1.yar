rule Win_Adware_Deskbar_1
{
strings:
	$a0 = { 6465736b6261722e646c6c }

	$a1 = { 5c43757272656e7456657273696f6e5c52756e4f6e6365[0-9]3332202f73 }


condition:
	$a0 and $a1
}