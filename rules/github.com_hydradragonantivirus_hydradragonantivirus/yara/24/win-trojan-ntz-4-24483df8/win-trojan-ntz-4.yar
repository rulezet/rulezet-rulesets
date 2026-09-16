rule Win_Trojan_NTZ_4
{
strings:
	$a0 = { cd21888e2d01b930018db65e018dbe7602a48a86760232862d01888676028d7cff8db67602a4 }


condition:
	$a0
}