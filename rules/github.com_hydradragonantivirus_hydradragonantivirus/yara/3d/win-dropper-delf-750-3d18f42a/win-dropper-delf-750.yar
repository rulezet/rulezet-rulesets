rule Win_Dropper_Delf_750
{
strings:
	$a0 = { 6a008d442404506a1e685480fd136af5e8b6dfffff50e8d0dfffff6a008d442404506a02689430fd136af5e89bdfffff50e8b5dfffff5a }


condition:
	$a0
}