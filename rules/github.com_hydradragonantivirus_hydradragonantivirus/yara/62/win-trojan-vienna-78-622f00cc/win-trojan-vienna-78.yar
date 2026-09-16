rule Win_Trojan_Vienna_78
{
strings:
	$a0 = { 908bd681ea6902cd219072203d5303751bb8004233 }


condition:
	$a0
}