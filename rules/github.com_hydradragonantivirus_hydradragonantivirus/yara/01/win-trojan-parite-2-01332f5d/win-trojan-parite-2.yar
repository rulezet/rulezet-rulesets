rule Win_Trojan_Parite_2
{
strings:
	$a0 = { f1f8bd506984ffe2e562ff916f8475181a2ebcb61af6b61a6884510cc67900e41f3ef764ea8c0091ba8475181a3ebcb41aeeb61a6884520c167900e413bb74f2 }


condition:
	$a0
}