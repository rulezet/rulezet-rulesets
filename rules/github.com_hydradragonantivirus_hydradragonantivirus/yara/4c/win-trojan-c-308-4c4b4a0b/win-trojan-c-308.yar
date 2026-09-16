rule Win_Trojan_C_308
{
strings:
	$a0 = { 52656164204fed6e6c7921 }

	$a1 = { 2f6175fd746f72756e29 }

	$a2 = { 22566952758d53 }

	$a3 = { 22484b4355ff5c534f4654574152 }


condition:
	$a0 and $a1 and $a2 and $a3
}