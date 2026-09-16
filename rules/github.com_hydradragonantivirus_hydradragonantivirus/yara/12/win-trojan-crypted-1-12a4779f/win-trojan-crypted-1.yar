rule Win_Trojan_Crypted_1
{
strings:
	$a0 = { e8040000008360eb0c5deb054555eb04b8ebf900c3e8000000005d81edbc1a4000eb01 }


condition:
	$a0
}