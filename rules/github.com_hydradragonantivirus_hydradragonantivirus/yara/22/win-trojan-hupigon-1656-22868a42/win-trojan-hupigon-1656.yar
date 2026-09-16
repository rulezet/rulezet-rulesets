rule Win_Trojan_Hupigon_1656
{
strings:
	$a0 = { 4aa6da63ed4ddb155eca89fc805f038b765db7ac48de576b7333540ed2425b918611ae84a789564d5bcda34ae88e35dd111b268e8942289720051fc6ddd0dbda9a }


condition:
	$a0
}