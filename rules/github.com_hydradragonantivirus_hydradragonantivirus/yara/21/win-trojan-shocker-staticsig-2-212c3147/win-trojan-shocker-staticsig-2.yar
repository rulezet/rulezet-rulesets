rule Win_Trojan_Shocker_staticsig_2
{
strings:
	$a0 = { b29b142c7c577b7986ad8f4f6f45b4fb13 }


condition:
	$a0
}