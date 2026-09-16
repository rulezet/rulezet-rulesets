rule Win_Trojan_Lct_1
{
strings:
	$a0 = { 81c72902890c891561c38bd581c24b02b8023dcd217303e927008bf581c659028904c38b }


condition:
	$a0
}