rule Win_Trojan_Vundo_452
{
strings:
	$a0 = { 50eb0a6b6a6061636e6266606ce9af05000003c6 }

	$a1 = { 616460636a626b616e636c6c65656c6c }


condition:
	$a0 and $a1
}