rule Win_Adware_Aureate_1
{
strings:
	$a0 = { 42726f777365722048656c706572204f626a65637473 }

	$a1 = { 41757265617465 }

	$a2 = { 446f776e6c6f61644f66666c696e654164 }


condition:
	$a0 and $a1 and $a2
}