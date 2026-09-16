rule Win_Trojan_Ply_1
{
strings:
	$a0 = { 03d590cd21908bd890b8024233c99033d290cd2190b8e01f052020b91714ba000103d590cd }


condition:
	$a0
}