rule Win_Downloader_9562_1
{
strings:
	$a0 = { a198ac0010e81dadffff8bd0b89cac0010e881aeffffb8a0ac0010ba4c8d0010e852faffffa198ac0010e8f8acffff50b89cac0010e815aeffff50b898ac0010e80aaeffff }


condition:
	$a0
}