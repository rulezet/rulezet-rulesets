rule Win_Trojan_USSR_8
{
strings:
	$a0 = { 3f50268b05d1e83598122e038415005883c304e2ea2ec684b70030 }


condition:
	$a0
}