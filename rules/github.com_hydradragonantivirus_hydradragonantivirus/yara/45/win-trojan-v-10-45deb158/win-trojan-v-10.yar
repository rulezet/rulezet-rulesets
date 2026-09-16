rule Win_Trojan_V_10
{
strings:
	$a0 = { b8014333c9cd210e1f72598b36040181343412b8004233d2cd21b4408b0e0601ba0001cd21 }


condition:
	$a0
}