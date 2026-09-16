rule Win_Trojan_Sinowal_53
{
strings:
	$a0 = { 909c50909005cb6f00000bc358e9f5030000e970 }

	$a1 = { 356364282d673c212a40376226382c5b2b632d603a38 }


condition:
	$a0 and $a1
}