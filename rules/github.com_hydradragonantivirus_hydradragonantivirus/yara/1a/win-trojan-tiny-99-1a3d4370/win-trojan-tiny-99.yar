rule Win_Trojan_Tiny_99
{
strings:
	$a0 = { 5d8bfe8d76??57a5a4ba????b80325cd218bd5b44ecc7301c3 }


condition:
	$a0
}