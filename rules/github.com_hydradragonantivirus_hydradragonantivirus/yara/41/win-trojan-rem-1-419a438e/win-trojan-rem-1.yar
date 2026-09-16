rule Win_Trojan_Rem_1
{
strings:
	$a0 = { 72656d2d776f726d }

	$a1 = { 25636f6d7370656325206e756c202f66202f63 }

	$a2 = { 636f7079202f622025302b25302e62617420252571 }


condition:
	$a0 and $a1 and $a2
}