rule Win_Trojan_Win_64
{
strings:
	$a0 = { 8b0424609ce8040000006770817c5d81ed111040008985111040008d }


condition:
	$a0
}