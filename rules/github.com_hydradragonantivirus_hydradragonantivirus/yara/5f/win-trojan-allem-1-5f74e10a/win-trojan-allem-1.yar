rule Win_Trojan_Allem_1
{
strings:
	$a0 = { 617363286d696428616e746f6e2c692c312929 }


condition:
	$a0
}