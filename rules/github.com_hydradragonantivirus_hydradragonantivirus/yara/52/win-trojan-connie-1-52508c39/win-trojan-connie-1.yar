rule Win_Trojan_Connie_1
{
strings:
	$a0 = { 33ffcd11b4522e9cfc8b73facd21b4268b5502268e59fe395d0656744f80ee05895d06cd21803d4d7405803d5a }


condition:
	$a0
}