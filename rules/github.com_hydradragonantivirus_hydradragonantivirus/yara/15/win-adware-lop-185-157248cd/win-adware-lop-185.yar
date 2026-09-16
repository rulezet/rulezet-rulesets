rule Win_Adware_Lop_185
{
strings:
	$a0 = { 3c05d6b00e60b09807d4becaec3cd3fbc094eaf22abbba6f69ef719de9b36a248de526a2d6f3f81cd935312b7819782d0b590ddfbad2ed44e1ce6409 }


condition:
	$a0
}