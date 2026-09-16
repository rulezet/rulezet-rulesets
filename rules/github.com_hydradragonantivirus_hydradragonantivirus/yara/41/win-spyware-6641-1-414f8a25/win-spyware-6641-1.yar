rule Win_Spyware_6641_1
{
strings:
	$a0 = { 605233ca596183d853e80c00000000 }


condition:
	$a0
}