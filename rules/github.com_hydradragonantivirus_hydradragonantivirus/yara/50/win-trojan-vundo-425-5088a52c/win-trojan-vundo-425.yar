rule Win_Trojan_Vundo_425
{
strings:
	$a0 = { 558bec538b5d08568b750c85f6578b7d10750383fe01eb409acf601d961bbc495227d835cef3b4e10a7f504d06cbac79 }


condition:
	$a0
}