rule Win_Dropper_Agent_34723
{
strings:
	$a0 = { 558bec6aff6878204000687018400064a100000000506489250000000083ec }

	$a1 = { 6a0a5850565353ff1524 }


condition:
	$a0 and $a1
}