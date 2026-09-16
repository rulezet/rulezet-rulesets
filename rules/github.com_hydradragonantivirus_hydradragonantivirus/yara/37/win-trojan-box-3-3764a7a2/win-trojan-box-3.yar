rule Win_Trojan_Box_3
{
strings:
	$a0 = { 050055c043000000ffff02030000a21d0000080000000203 }


condition:
	$a0
}