rule Win_Trojan_Shek_1
{
strings:
	$a0 = { ec56be0200eb1533c05033c033d25052b863005056e81c0583c40a4683fe197ce65e5dc3558b }


condition:
	$a0
}