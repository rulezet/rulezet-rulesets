rule Win_Dropper_Turd_1
{
strings:
	$a0 = { 20747572642e636f6d0d000000ba0000b8e001ffd08db62500b8e401ffd08db66500b8e401 }


condition:
	$a0
}