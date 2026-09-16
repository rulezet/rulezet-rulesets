rule Win_Trojan_DW_1
{
strings:
	$a0 = { de7e77aef3ae2b27257326d4e22161727ba6e4279165e8047f7d5773b5b5757726232725a6f7259c }


condition:
	$a0
}