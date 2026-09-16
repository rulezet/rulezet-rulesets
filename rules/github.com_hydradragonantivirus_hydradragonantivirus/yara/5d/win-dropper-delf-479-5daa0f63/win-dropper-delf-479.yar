rule Win_Dropper_Delf_479
{
strings:
	$a0 = { 8945b8681837400068c4364000e85eeaffff50e860eaffff8945c4682437400068c43640 }


condition:
	$a0
}