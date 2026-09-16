rule Win_Trojan_Tburg_1
{
strings:
	$a0 = { 0500f7e150b419cd2133d2b90500bb00025052cd2572549d5a585951bb000203d98037abe2f6b9 }


condition:
	$a0
}