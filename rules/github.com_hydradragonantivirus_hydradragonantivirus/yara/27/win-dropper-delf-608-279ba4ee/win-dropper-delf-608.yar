rule Win_Dropper_Delf_608
{
strings:
	$a0 = { 5568ef48001064ff306489206a3468fc48001068084900106a00e80ff6ffff83f8067405e8c9 }


condition:
	$a0
}