rule Win_Trojan_Bancos_1823
{
strings:
	$a0 = { 55834581a77fcbd0168cbcc82fee515187d914fc6d3ee91b7ac0499190058ee31823daf47b99ecd7bd003dde956c9622ff0edeb87dd6a0ee51b4e2f5d06e585fa753c3141f53 }


condition:
	$a0
}